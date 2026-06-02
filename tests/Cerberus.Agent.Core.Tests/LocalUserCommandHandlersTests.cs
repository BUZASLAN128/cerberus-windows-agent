using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.Core.Tests;

public sealed class LocalUserCommandHandlersTests
{
    [Fact]
    public async Task CreateManagedUser_DeniesCreateWhenPolicyDisabled()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers()
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "cerb_sennu_k7m2q6x4" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("disabled by local agent policy", result.Stderr);
        Assert.Contains("local_user_create_disabled_by_policy", Convert.ToString(result.PostVerify));
    }

    [Fact]
    public async Task CreateManagedUser_RejectsUsernameWithoutManagedPrefix()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "Administrator", audit_correlation_id = "audit-id" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("local account limits", result.Stderr);
    }

    [Fact]
    public async Task DeleteManagedUser_RejectsMissingAuditCorrelation()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.delete");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "cerb_sennu_k7m2q6x4" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("audit correlation", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_AcceptsManagedUsernameShapeBeforeAuditGate()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "cerb_sennu_k7m2q6x4" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("audit correlation", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsUsernameOverWindowsLocalLimit()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "cerb_sennu_k7m2q6x4x", audit_correlation_id = "audit-id" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("local account limits", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsManagedUsernameWithInvalidBase32Suffix()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "cerb_sennu_k7m2q9x4", audit_correlation_id = "audit-id" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("local account limits", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsCurrentManagedUsernameWithoutMarkerIdentity()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("assignment, account, membership, and marker", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsInvalidCredentialPublicKeyBeforeMutation()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_public_key_pem = "not-a-pem",
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("public key", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsWeakCredentialPublicKeyBeforeMutation()
    {
        using var rsa = RSA.Create(1024);
        var publicPem = PublicKeyPem(rsa);
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_public_key_pem = publicPem,
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("2048", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsCredentialPublicKeyWithoutFingerprintBeforeMutation()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = PublicKeyPem(rsa);
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_public_key_pem = publicPem,
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("fingerprint", result.Stderr);
    }


    [Fact]
    public async Task CreateManagedUser_RejectsCredentialPublicKeyFingerprintMismatchBeforeMutation()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = PublicKeyPem(rsa);
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_public_key_pem = publicPem,
                credential_key_fingerprint = new string('0', 64),
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("fingerprint", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsInvalidRdpPublicKeyBeforeMutation()
    {
        var aad = "tenant|credential|rdp|1";
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                rdp_credential_profile_id = Guid.NewGuid().ToString(),
                rdp_tenant_key_id = "tenant-key",
                rdp_key_version = 1,
                rdp_public_key_pem = "not-a-pem",
                rdp_cipher_alg = "aes256gcm+rsa-oaep",
                rdp_aad = aad,
                rdp_aad_hash = Sha256Hex(aad),
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("RDP credential public key", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsRdpAadHashMismatchBeforeMutation()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = PublicKeyPem(rsa);
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                rdp_credential_profile_id = Guid.NewGuid().ToString(),
                rdp_tenant_key_id = "tenant-key",
                rdp_key_version = 1,
                rdp_public_key_pem = publicPem,
                rdp_public_key_fingerprint = Sha256HexAscii(publicPem),
                rdp_cipher_alg = "aes256gcm+rsa-oaep",
                rdp_aad = "tenant|credential|rdp|1",
                rdp_aad_hash = new string('0', 64),
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("AAD hash", result.Stderr);
    }

    [Fact]
    public void BuildRdpCredentialEnvelope_EncryptsPasswordWithoutPlaintextFields()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = PublicKeyPem(rsa);
        var credentialId = Guid.NewGuid().ToString();
        var aad = $"tenant-id|{credentialId}|rdp|1";
        var payload = LocalUserPayload(
            username: "cerb_sennu_k7m2q6x4",
            credentialProfileId: credentialId,
            tenantKeyId: "tenant-key",
            publicPem: publicPem,
            aad: aad);
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("BuildRdpCredentialEnvelope", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var envelope = Assert.IsType<Dictionary<string, object?>>(
            method.Invoke(null, new[] { "S3cure!Password42", payload }));

        Assert.Equal("password", envelope["auth_type"]);
        Assert.Equal(credentialId, envelope["credential_id"]);
        Assert.Equal("cerb_sennu_k7m2q6x4", envelope["username_hint"]);
        Assert.Equal("tenant-key", envelope["tenant_key_id"]);
        Assert.Equal("aes256gcm+rsa-oaep", envelope["cipher_alg"]);
        Assert.DoesNotContain("S3cure!Password42", Convert.ToString(envelope["ciphertext"]));

        var wrappedDek = Convert.FromBase64String(Assert.IsType<string>(envelope["wrapped_dek"]));
        var nonce = Convert.FromBase64String(Assert.IsType<string>(envelope["cipher_nonce"]));
        var cipherWithTag = Convert.FromBase64String(Assert.IsType<string>(envelope["ciphertext"]));
        var dek = rsa.Decrypt(wrappedDek, RSAEncryptionPadding.OaepSHA256);
        var ciphertext = cipherWithTag[..^16];
        var tag = cipherWithTag[^16..];
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(dek, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(aad));
        var json = Encoding.UTF8.GetString(plaintext);
        Assert.Contains("S3cure!Password42", json);
        Assert.Contains("cerb_sennu_k7m2q6x4", json);
    }

    [Fact]
    public void GeneratePassword_HasNoFixedSuffixAndSatisfiesComplexity()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("GeneratePassword", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var password = Assert.IsType<string>(method.Invoke(null, Array.Empty<object>()));

        Assert.True(password.Length >= 24);
        Assert.False(password.EndsWith("aA1!", StringComparison.Ordinal));
        Assert.Matches("[a-z]", password);
        Assert.Matches("[A-Z]", password);
        Assert.Matches("[0-9]", password);
        Assert.Matches("[!@#$%^*\\-_+=]", password);
    }

    [Fact]
    public void ManagedMarkerToken_IncludesTerminatorToPreventPrefixMatch()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("ManagedMarkerToken", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var marker = Assert.IsType<string>(method.Invoke(null, ["123"]));
        var prefixedMarker = Assert.IsType<string>(method.Invoke(null, ["cerberus-managed-local-user:123"]));
        var longerMarkerDescription = "cerberus-managed-local-user:12345; assignment=a; account=b";

        Assert.Equal("cerberus-managed-local-user:123;", marker);
        Assert.Equal(marker, prefixedMarker);
        Assert.DoesNotContain(marker, longerMarkerDescription, StringComparison.Ordinal);
    }

    [Fact]
    public void ManagedDescription_DoesNotExposeInternalMarkerOrIds()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("ManagedDescription", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var payload = LocalUserPayload(
            "cerb_sennu_k7m2q6x4",
            "credential-profile-id",
            "tenant-key-id",
            "public-key",
            "aad");
        var description = Assert.IsType<string>(method.Invoke(null, [payload]));

        Assert.Equal("Cerberus managed local account.", description);
        Assert.DoesNotContain("cerberus-managed-local-user", description, StringComparison.Ordinal);
        Assert.DoesNotContain("assignment-id", description, StringComparison.Ordinal);
        Assert.DoesNotContain("account-id", description, StringComparison.Ordinal);
    }

    [Fact]
    public void ApplyManagedPasswordPolicyFlags_PreventsUserChangeAndExpiry()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("ApplyManagedPasswordPolicyFlags", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var flags = Assert.IsType<int>(method.Invoke(null, [0]));

        Assert.True((flags & 0x0040) != 0);
        Assert.True((flags & 0x10000) != 0);
    }

    [Fact]
    public void IsAllowedUsername_AcceptsOnlyCurrentManagedShape()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("IsAllowedUsername", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        Assert.True(Assert.IsType<bool>(method.Invoke(null, ["cerb_sennu_k7m2q6x4"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, ["cerbtest_unit"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, ["sennurcop_k7m2q6x4aa"])));
    }

    [Fact]
    public void TryAcquireMutationSlot_RateLimitsDuplicateMutationForSameUser()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("TryAcquireMutationSlot", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var now = DateTimeOffset.UtcNow;
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        var suffixBytes = RandomNumberGenerator.GetBytes(8);
        var username = "cerb_ratea_" + new string(suffixBytes.Select(item => alphabet[item % alphabet.Length]).ToArray());
        var args = new object?[] { "create", username, now, null };

        Assert.True(Assert.IsType<bool>(method.Invoke(null, args)));

        args = ["create", username, now.AddMilliseconds(100), null];
        Assert.False(Assert.IsType<bool>(method.Invoke(null, args)));
        Assert.True(Assert.IsType<TimeSpan>(args[3]) > TimeSpan.Zero);

        args = ["disable", username, now.AddMilliseconds(100), null];
        Assert.True(Assert.IsType<bool>(method.Invoke(null, args)));
    }

    [Fact]
    public void IsDomainControllerProductType_OnlyMatchesLanmanNt()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("IsDomainControllerProductType", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        Assert.True(Assert.IsType<bool>(method.Invoke(null, ["LanmanNT"])));
        Assert.True(Assert.IsType<bool>(method.Invoke(null, ["lanmannt"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, ["ServerNT"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, ["WinNT"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, [null])));
    }

    [Fact]
    public void EnsureLocalAccountsSupportedForProductType_FailsClosedOnDomainControllers()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("EnsureLocalAccountsSupportedForProductType", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var payload = LocalUserPayload(
            "cerb_sennu_k7m2q6x4",
            "credential-profile-id",
            "tenant-key-id",
            "public-key",
            "aad");

        var result = Assert.IsType<CommandResult>(method.Invoke(null, ["LanmanNT", payload]));

        Assert.Equal("FAILED", result.Status);
        Assert.Equal(2, result.ExitCode);
        Assert.Contains("domain controllers", result.Stderr);
        Assert.Contains("local_accounts_unsupported_on_domain_controller", Convert.ToString(result.PostVerify));

        Assert.Null(method.Invoke(null, ["ServerNT", payload]));
        Assert.Null(method.Invoke(null, ["WinNT", payload]));
    }

    private static string PublicKeyPem(RSA rsa)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN PUBLIC KEY-----");
        builder.AppendLine(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END PUBLIC KEY-----");
        return builder.ToString();
    }

    private static string Sha256Hex(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string Sha256HexAscii(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(value))).ToLowerInvariant();

    private static object LocalUserPayload(
        string username,
        string credentialProfileId,
        string tenantKeyId,
        string publicPem,
        string aad)
    {
        var payloadType = typeof(LocalUserCommandHandlers)
            .GetNestedType("LocalUserPayload", BindingFlags.NonPublic);
        Assert.NotNull(payloadType);
        return Activator.CreateInstance(
            payloadType,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args:
            [
                username,
                "audit-id",
                "Sennur Copcu",
                "managed-account-id",
                "assignment-id",
                "membership-user-id",
                "marker-id",
                "credential-request-id",
                null,
                null,
                credentialProfileId,
                tenantKeyId,
                1,
                publicPem,
                Sha256HexAscii(publicPem),
                "aes256gcm+rsa-oaep",
                aad,
                Sha256Hex(aad),
                null,
            ],
            culture: null)!;
    }
}
