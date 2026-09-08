using Cerberus.Agent.Integrations.Ad;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cerberus.Agent.Core.Tests;

// Support evidence only: no connection to a domain, service identity, or protected machine filesystem.
public sealed class ScopedAdUserProviderTests
{
    private static readonly AdAccountBinding Binding = new("tenant", "agent", "account", "assignment", "scope", "cerb_test");
    private static readonly AdScope Scope = new("scope", "dc.example.test", Guid.NewGuid(), Guid.NewGuid(), "example.test");
    private const string Password = "Generated-Only-Offline-Test-Password-29!";

    [Fact]
    public async Task Prepare_ReplaysSameEncryptedPassword_ThenActivateRequiresMatchingProfileAndObject()
    {
        using var rsa = RSA.Create(2048);
        var request = CredentialRequest(rsa);
        var store = new Store();
        var directory = new Directory(store);
        var provider = Provider(directory, store);
        var target = new AdCommandTarget(Binding, Scope.DomainGuid, Scope.OuGuid, Scope.DomainDnsName!);
        var prepared = await provider.PrepareAsync(target, request, default);
        Assert.Equal("ad_prepared", prepared.Code);
        Assert.True(directory.User!.Disabled);
        Assert.Equal(prepared.PreparedCredential, store.Record!.PreparedCredential);
        var envelope = prepared.PreparedCredential!.Envelope;
        var encrypted = Convert.FromBase64String(envelope.Ciphertext);
        var plaintext = new byte[encrypted.Length - 16];
        var dek = rsa.Decrypt(Convert.FromBase64String(envelope.WrappedDek), RSAEncryptionPadding.OaepSHA256);
        using (var aes = new AesGcm(dek, 16))
            aes.Decrypt(Convert.FromBase64String(envelope.CipherNonce), encrypted.AsSpan(0, plaintext.Length),
                encrypted.AsSpan(plaintext.Length), plaintext, Encoding.UTF8.GetBytes(request.Metadata.Aad!));
        using var decoded = JsonDocument.Parse(plaintext);
        Assert.Equal(directory.PasswordSet, decoded.RootElement.GetProperty("password").GetString());
        Assert.Equal(Binding.Username, decoded.RootElement.GetProperty("username").GetString());
        Assert.Equal(Scope.DomainDnsName, decoded.RootElement.GetProperty("domain").GetString());
        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(dek);
        directory.FailPassword = true;
        Assert.Equal(prepared.PreparedCredential, (await provider.PrepareAsync(target, request, default)).PreparedCredential);
        Assert.Equal("ad_credential_pending", (await provider.PrepareAsync(target, request with { CredentialRequestId = Guid.NewGuid().ToString() }, default)).Code);
        Assert.Equal("ad_credential_pending", (await provider.ActivateAsync(target, prepared.Identity!, "wrong", default)).Code);
        Assert.Equal("ad_ownership_mismatch", (await provider.ActivateAsync(target, prepared.Identity! with { ObjectGuid = Guid.NewGuid() }, request.Metadata.CredentialProfileId!, default)).Code);
        Assert.True(directory.User.Disabled);
        Assert.Equal("ad_activated", (await provider.ActivateAsync(target, prepared.Identity!, request.Metadata.CredentialProfileId!, default)).Code);
        Assert.False(directory.User.Disabled);
        Assert.Equal("ad_disabled", (await provider.DisableAsync(target, prepared.Identity!, "requested", default)).Code);
        Assert.Equal("ad_account_disabled", (await provider.ActivateAsync(target, prepared.Identity!, request.Metadata.CredentialProfileId!, default)).Code);
    }

    [Fact]
    public async Task Prepare_PasswordFailureCanResumeDisabled_ExpiredRecordsRemainUsableForDisable()
    {
        using var rsa = RSA.Create(2048);
        var request = CredentialRequest(rsa);
        var store = new Store();
        var directory = new Directory(store) { FailPassword = true };
        var provider = Provider(directory, store);
        var target = new AdCommandTarget(Binding, Scope.DomainGuid, Scope.OuGuid, Scope.DomainDnsName!);
        Assert.False((await provider.PrepareAsync(target, request, default)).Success);
        Assert.NotNull(store.Record!.PreparedCredential);
        Assert.False(store.Record.PasswordInitialized);
        Assert.True(directory.User!.Disabled);
        var originalIdentity = directory.User.Identity;
        directory.FailPassword = false;
        Assert.True((await provider.PrepareAsync(target, request, default)).Success);
        Assert.Equal(originalIdentity, directory.User.Identity);
        var prepared = store.Record.PreparedCredential!;
        var expired = store.Record with { PreparedCredential = prepared with { Request = request with { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1) } } };
        Assert.Equal(expired, ProtectedAdOwnershipStore.Decode(JsonSerializer.SerializeToUtf8Bytes(expired)));
        store.Record = expired;
        Assert.Equal("ad_credential_expired", (await provider.ActivateAsync(target, originalIdentity, request.Metadata.CredentialProfileId!, default)).Code);
        Assert.True((await provider.DisableAsync(target, originalIdentity, "requested", default)).Success);
        Assert.True(directory.User.Disabled);
    }

    [Fact]
    public void PreparedEnvelope_CorruptionAndPostInitializationReplacementFailClosed()
    {
        using var rsa = RSA.Create(2048);
        var request = CredentialRequest(rsa);
        var envelope = RdpCredentialCodec.Encrypt(Password, Binding.Username, Scope.DomainDnsName, request.Metadata);
        var record = new AdOwnership(Binding, Scope, new(Guid.NewGuid(), "S-1-5-21-1-2-3-1100"), true, false, PreparedCredential: new(request, envelope));
        Assert.Equal(record, ProtectedAdOwnershipStore.Decode(JsonSerializer.SerializeToUtf8Bytes(record)));
        foreach (var broken in new[] { envelope with { CipherNonce = "bad" }, envelope with { UsernameHint = "foreign" },
            envelope with { Domain = "foreign.test" }, envelope with { CredentialId = "foreign" }, envelope with { WrappedDek = "" } })
        {
            var changed = record with { PreparedCredential = new(request, broken) };
            Assert.Equal("ad_ownership_invalid", Assert.Throws<AdOperationDeniedException>(() =>
                ProtectedAdOwnershipStore.Decode(JsonSerializer.SerializeToUtf8Bytes(changed))).Code);
            Assert.Throws<AdOperationDeniedException>(() => ProtectedAdOwnershipStore.ValidateTransition(record, changed));
        }
        ProtectedAdOwnershipStore.ValidateTransition(record, record with { DisableRequested = true });
    }

    internal static AdCredentialRequest CredentialRequest(RSA rsa)
    {
        var pem = rsa.ExportSubjectPublicKeyInfoPem();
        const string aad = "scoped-ad-support-test";
        return new(Guid.NewGuid().ToString(), DateTimeOffset.UtcNow.AddMinutes(10), new(Guid.NewGuid().ToString(), "tenant-key", 1,
            pem, Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(pem))).ToLowerInvariant(), "aes256gcm+rsa-oaep", aad,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(aad))).ToLowerInvariant()));
    }

    [Fact]
    public async Task Create_PersistsOwnershipBeforeActivation_ThenRequiresDisableBeforeDelete()
    {
        var store = new Store();
        var directory = new Directory(store);
        var provider = Provider(directory, store);
        var created = await provider.CreateAsync(Binding, Password, true, default);
        Assert.True(created.Success);
        Assert.False(directory.User!.Disabled);
        Assert.Equal(created.Identity, store.Record!.Identity);
        Assert.True(store.Record.PasswordInitialized);
        Assert.Equal("ad_disable_before_delete", (await provider.DeleteAsync(Binding, true, "requested", default)).Code);
        Assert.True((await provider.DisableAsync(Binding, "requested", default)).Success);
        Assert.True(directory.User.Disabled);
        Assert.Equal("ad_account_disabled", (await provider.CreateAsync(Binding, Password, true, default)).Code);
        Assert.True((await provider.DeleteAsync(Binding, true, "requested", default)).Success);
        Assert.Null(directory.User);
        Assert.True(store.Record.Deleted);
        Assert.True((await provider.DeleteAsync(Binding, true, "retry", default)).Success);
        Assert.Equal("ad_account_retired", (await provider.CreateAsync(Binding, Password, true, default)).Code);
    }

    [Fact]
    public async Task PersistenceFailure_LeavesDisabledUnownedUser_AndRetryCannotAdopt()
    {
        var store = new Store { FailWrite = true };
        var directory = new Directory(store);
        var provider = Provider(directory, store);
        Assert.False((await provider.CreateAsync(Binding, Password, true, default)).Success);
        Assert.True(directory.User!.Disabled);
        Assert.Null(store.Record);
        store.FailWrite = false;
        Assert.Equal("ad_unowned_collision", (await provider.CreateAsync(Binding, Password, true, default)).Code);
        Assert.True(directory.User.Disabled);
    }

    [Theory]
    [InlineData("guid")]
    [InlineData("sid")]
    [InlineData("parent")]
    [InlineData("protected")]
    [InlineData("child")]
    public async Task OwnedObjectDrift_DeniesDisableAndDelete(string drift)
    {
        var store = new Store();
        var directory = new Directory(store);
        var provider = Provider(directory, store);
        Assert.True((await provider.CreateAsync(Binding, Password, false, default)).Success);
        var user = directory.User!;
        directory.User = drift switch
        {
            "guid" => user with { Identity = user.Identity with { ObjectGuid = Guid.NewGuid() } },
            "sid" => user with { Identity = user.Identity with { Sid = "other-sid" } },
            "parent" => user with { ParentGuid = Guid.NewGuid() },
            "protected" => user with { Protected = true },
            _ => user with { LeafUser = false }
        };
        // A replacement GUID is absent under the owned GUID: disable fails and deletion tombstones only the missing original.
        Assert.False((await provider.DisableAsync(Binding, "requested", default)).Success);
        var deleted = await provider.DeleteAsync(Binding, true, "requested", default);
        Assert.Equal(drift == "guid", deleted.Success);
        Assert.NotNull(directory.User);
    }

    [Fact]
    public async Task MissingUnownedAndWrongAuthority_DoNotMutate()
    {
        var store = new Store();
        var directory = new Directory(store);
        var provider = Provider(directory, store);
        Assert.Equal("ad_ownership_required", (await provider.DeleteAsync(Binding, true, "requested", default)).Code);
        Assert.Equal("ad_scope_denied", (await provider.CreateAsync(Binding with { TenantId = "other" }, Password, true, default)).Code);
        Assert.Equal("ad_scope_denied", (await provider.CreateAsync(Binding with { ScopeId = "other" }, Password, true, default)).Code);
        Assert.Null(directory.User);
        Assert.Null(store.Record);
    }

    [Fact]
    public async Task OwnedPartialCreate_ResumesOnlySameBinding_WithoutDuplicateCreation()
    {
        var store = new Store();
        var directory = new Directory(store) { FailPassword = true };
        var provider = Provider(directory, store);
        Assert.False((await provider.CreateAsync(Binding, Password, true, default)).Success);
        var original = directory.User!.Identity;
        Assert.False(store.Record!.PasswordInitialized);
        directory.FailPassword = false;
        Assert.Equal("ad_ownership_mismatch", (await provider.CreateAsync(Binding with { AssignmentId = "other" }, Password, true, default)).Code);
        Assert.True((await provider.CreateAsync(Binding, Password, true, default)).Success);
        Assert.Equal(original, directory.User.Identity);
        Assert.False(directory.User.Disabled);
    }

    [Fact]
    public async Task MissingConfirmation_DoesNotDeleteOwnedDisabledAccount()
    {
        var store = new Store();
        var directory = new Directory(store);
        var provider = Provider(directory, store);
        Assert.True((await provider.CreateAsync(Binding, Password, false, default)).Success);
        Assert.Equal("ad_delete_confirmation_required", (await provider.DeleteAsync(Binding, false, "requested", default)).Code);
        Assert.Equal("ad_delete_confirmation_required", (await provider.DeleteAsync(Binding, true, "", default)).Code);
        Assert.NotNull(directory.User);
        Assert.False(store.Record!.Deleted);
    }

    [Fact]
    public async Task CancelledBeforeExecution_ReturnsTypedFailureWithoutMutation()
    {
        var store = new Store();
        var directory = new Directory(store);
        var result = await Provider(directory, store).CreateAsync(Binding, Password, true, new CancellationToken(true));
        Assert.Equal("ad_cancelled_before_execution", result.Code);
        Assert.False(result.Success);
        Assert.Null(directory.User);
        Assert.Null(store.Record);
    }

    [Fact]
    public async Task CreateReplay_ReportsExistingWithoutChangingPassword_OrDisablingEnabledUser()
    {
        var store = new Store();
        var directory = new Directory(store);
        var provider = Provider(directory, store);
        Assert.True((await provider.CreateAsync(Binding, Password, true, default)).Success);
        directory.FailPassword = true;
        Assert.Equal("ad_existing", (await provider.CreateAsync(Binding, Password + "new", true, default)).Code);
        Assert.False((await provider.CreateAsync(Binding, Password, false, default)).Success);
        Assert.False(directory.User!.Disabled);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("{}")]
    [InlineData("{\"Binding\":null,\"Identity\":null,\"Scope\":null}")]
    [InlineData("{broken")]
    public void CorruptOwnership_ReturnsExplicitDenial(string json)
    {
        var error = Assert.Throws<AdOperationDeniedException>(() => ProtectedAdOwnershipStore.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
        Assert.Equal("ad_ownership_invalid", error.Code);
    }

    private static ScopedAdUserProvider Provider(Directory directory, Store store) =>
        new(new AgentIdentity("agent", "tenant"), new[] { Scope }, directory, store);

    private sealed class Store : IAdOwnershipStore
    {
        public AdOwnership? Record;
        public bool FailWrite;
        public IDisposable AcquireLease(AdAccountBinding binding) => new Lease();
        public AdOwnership? Read(AdAccountBinding binding) => Record;
        public void Write(AdOwnership ownership)
        {
            if (FailWrite) throw new IOException("Simulated write failure");
            Record = ownership;
        }
        private sealed class Lease : IDisposable { public void Dispose() { } }
    }

    private sealed class Directory(Store store) : IAdDirectoryBoundary, IAdDirectorySession
    {
        public AdUserState? User;
        public bool FailPassword;
        public string? PasswordSet;
        public IAdDirectorySession Open(AdScope scope, CancellationToken ct = default) => this;
        public void VerifyScope() { }
        public AdUserState? FindUsername(string username) => User;
        public AdUserState? Read(Guid id) => User?.Identity.ObjectGuid == id ? User : null;
        public AdUserState CreateDisabled(string username) => User = new(new(Guid.NewGuid(), "S-1-5-21-1-2-3-1100"),
            Scope.OuGuid, username, true, false, true);
        public void InitializePassword(AdUserIdentity identity, string username, string password)
        {
            Assert.True(User!.Disabled);
            Assert.Equal(identity, store.Record!.Identity);
            if (FailPassword) throw new IOException("Simulated password initialization failure");
            if (store.Record.PreparedCredential is not null) Assert.False(store.Record.PasswordInitialized);
            PasswordSet = password;
        }
        public void SetDisabled(AdUserIdentity identity, string username, bool disabled)
        {
            Assert.Equal(identity, store.Record!.Identity);
            if (!disabled) Assert.True(store.Record.PasswordInitialized);
            User = User! with { Disabled = disabled };
        }
        public void DeleteLeaf(AdUserIdentity identity, string username)
        {
            Assert.True(User!.Disabled);
            Assert.Equal(identity, User.Identity);
            User = null;
        }
        public void Dispose() { }
    }
}
