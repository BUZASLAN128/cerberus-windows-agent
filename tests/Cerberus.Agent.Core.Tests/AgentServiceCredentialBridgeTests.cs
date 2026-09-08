using Cerberus.Agent.App.Actions;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentServiceCredentialBridgeTests
{
    [Fact]
    public async Task PromoteAsync_CopiesUserScopeRegistrationToMachineScopeStore()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var userStore = new DpapiSecretStore(SecretStoreScope.User, Path.Combine(root, "user"));
        var machineStore = new DpapiSecretStore(SecretStoreScope.User, Path.Combine(root, "machine"));
        var identity = new AgentIdentity("agent-id", "tenant-id");

        await userStore.SaveAsync(
            identity,
            "refresh-token",
            "private-key",
            "http://backend.local",
            "http://tailscale.local",
            "tskey-auth-secret",
            CancellationToken.None);

        var result = await AgentServiceCredentialBridge.PromoteAsync(userStore, machineStore, CancellationToken.None);
        var (storedIdentity, refreshToken, privateKey, backendUrl, loginServer, authKey) =
            await machineStore.LoadAsync(CancellationToken.None);

        Assert.Equal("agent-id", result.AgentId);
        Assert.Equal("tenant-id", result.TenantId);
        Assert.Equal(identity, storedIdentity);
        Assert.Equal("refresh-token", refreshToken);
        Assert.Equal("private-key", privateKey);
        Assert.Equal("http://backend.local", backendUrl);
        Assert.Equal("http://tailscale.local", loginServer);
        Assert.Equal("tskey-auth-secret", authKey);
    }

    [Fact]
    public async Task PromoteAsync_CanSyncRotatedMachineScopeTokenBackToUserScopeStore()
    {
        var userStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "stale-refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");
        var machineStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "rotated-refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local",
            tailscaleLoginServer: "http://tailscale.local",
            tailscaleAuthkey: "tskey-auth-secret");

        var result = await AgentServiceCredentialBridge.PromoteAsync(
            machineStore,
            userStore,
            CancellationToken.None);
        var (storedIdentity, refreshToken, _, _, loginServer, authKey) =
            await userStore.LoadAsync(CancellationToken.None);

        Assert.Equal("agent-id", result.AgentId);
        Assert.Equal("tenant-id", result.TenantId);
        Assert.Equal("agent-id", storedIdentity.AgentId);
        Assert.Equal("rotated-refresh-token", refreshToken);
        Assert.Equal("http://tailscale.local", loginServer);
        Assert.Equal("tskey-auth-secret", authKey);
    }

    [Fact]
    public async Task PromoteAndClearSourceAsync_ClearsUserScopeSecretsAfterMachineVerification()
    {
        var userStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");
        var machineStore = new InMemorySecretStore();

        var result = await AgentServiceCredentialBridge.PromoteAndClearSourceAsync(
            userStore,
            machineStore,
            CancellationToken.None);

        Assert.Equal("agent-id", result.AgentId);
        Assert.Equal(1, machineStore.SaveCount);
        Assert.Equal(1, userStore.ClearCount);
    }

    [Fact]
    public async Task PreserveMachineRegistrationForUserAsync_SyncsMachineScopeBackBeforeServiceUninstall()
    {
        var userStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "stale-refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");
        var machineStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "rotated-refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");

        var preserved = await AgentServiceProvisioning.PreserveMachineRegistrationForUserAsync(
            machineStore,
            userStore,
            machineRegistrationExpected: true,
            CancellationToken.None);
        var (_, refreshToken, _, _, _, _) = await userStore.LoadAsync(CancellationToken.None);

        Assert.True(preserved);
        Assert.Equal("rotated-refresh-token", refreshToken);
        Assert.Equal(1, userStore.SaveCount);
        Assert.Equal(0, machineStore.ClearCount);
    }

    [Fact]
    public async Task PreserveMachineRegistrationForUserAsync_DoesNothingWhenMachineCredentialMissing()
    {
        var userStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "stale-refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");
        var machineStore = new ThrowingLoadSecretStore();

        var preserved = await AgentServiceProvisioning.PreserveMachineRegistrationForUserAsync(
            machineStore,
            userStore,
            machineRegistrationExpected: false,
            CancellationToken.None);

        Assert.False(preserved);
        Assert.Equal(0, userStore.SaveCount);
    }

    [Fact]
    public async Task PreserveMachineRegistrationForUserAsync_FailsClosedWhenExpectedMachineCredentialCannotSync()
    {
        var userStore = new InMemorySecretStore();
        var machineStore = new ThrowingLoadSecretStore();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => AgentServiceProvisioning.PreserveMachineRegistrationForUserAsync(
                machineStore,
                userStore,
                machineRegistrationExpected: true,
                CancellationToken.None));

        Assert.Equal(0, userStore.SaveCount);
    }

    [Fact]
    public async Task DeactivateAndClearRegistrationAsync_FailsClosedWhenPortalDeactivateFails()
    {
        var store = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => AgentServiceProvisioning.DeactivateAndClearRegistrationAsync(
                store,
                (_, _, _, _) => Task.FromResult(false),
                CancellationToken.None));

        Assert.Equal(0, store.ClearCount);
    }

    [Fact]
    public async Task DeactivateAndClearRegistrationAsync_ClearsOnlyAfterPortalDeactivateSucceeds()
    {
        var store = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");

        var deactivated = await AgentServiceProvisioning.DeactivateAndClearRegistrationAsync(
            store,
            (_, reasonCode, reason, _) =>
            {
                Assert.Equal(AgentBackendLifecycle.UnregisterReasonCode, reasonCode);
                Assert.Equal(AgentBackendLifecycle.UnregisterReason, reason);
                return Task.FromResult(true);
            },
            CancellationToken.None);

        Assert.True(deactivated);
        Assert.Equal(1, store.ClearCount);
    }

    [Fact]
    public async Task MachineScopeSecret_DoesNotAddExplicitInteractiveUserAce()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var store = new DpapiSecretStore(SecretStoreScope.Machine, root);
        var currentSid = WindowsIdentity.GetCurrent().User;
        Assert.NotNull(currentSid);

        await store.SaveAsync(
            new AgentIdentity("agent-id", "tenant-id"),
            "refresh-token",
            "private-key",
            "http://backend.local",
            null,
            null,
            CancellationToken.None);

        var security = new FileInfo(Path.Combine(root, "secrets.json")).GetAccessControl();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier));

        var hasInteractiveUserAce = rules
            .OfType<FileSystemAccessRule>()
            .Any(rule => currentSid.Equals(rule.IdentityReference));

        Assert.False(hasInteractiveUserAce);
    }

    [Fact]
    public async Task PromoteAsync_FailsWhenUserScopeRegistrationIsIncomplete()
    {
        var userStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");
        var machineStore = new InMemorySecretStore();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => AgentServiceCredentialBridge.PromoteAsync(userStore, machineStore, CancellationToken.None));

        Assert.Equal(0, machineStore.SaveCount);
    }

    [Fact]
    public async Task PromoteAsync_FailsWhenDestinationStoreMutatesCredentialPayload()
    {
        var userStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local",
            tailscaleLoginServer: "http://tailscale.local",
            tailscaleAuthkey: "tskey-auth-secret");
        var machineStore = new MutatingSaveSecretStore();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => AgentServiceCredentialBridge.PromoteAsync(userStore, machineStore, CancellationToken.None));
    }

    [Fact]
    public async Task PrepareRegistrationForInstallAsync_StagesUserRegistrationWithoutReplacingMachine()
    {
        var userStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");
        var machineStore = new InMemorySecretStore(
            new AgentIdentity("stale-agent", "tenant-id"),
            refreshToken: "stale-refresh-token",
            privateKeyPem: "stale-private-key",
            backendUrl: "http://backend.local");

        var pendingStore = new InMemorySecretStore();
        var result = await AgentServiceProvisioning.PrepareRegistrationForInstallAsync(
            userStore,
            machineStore,
            pendingStore,
            CancellationToken.None);

        Assert.True(result.StagedFromUserScope);
        Assert.Equal(0, machineStore.SaveCount);
        var (storedIdentity, refreshToken, _, _, _, _) = await machineStore.LoadAsync(CancellationToken.None);
        Assert.Equal("stale-agent", storedIdentity.AgentId);
        Assert.Equal("stale-refresh-token", refreshToken);
        Assert.Equal("agent-id", (await pendingStore.LoadAsync(CancellationToken.None)).Identity.AgentId);
    }

    [Fact]
    public async Task PrepareRegistrationForInstallAsync_UsesMachineRegistrationForRepairWhenUserRegistrationMissing()
    {
        var userStore = new ThrowingLoadSecretStore();
        var machineStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "machine-refresh-token",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");

        var result = await AgentServiceProvisioning.PrepareRegistrationForInstallAsync(
            userStore,
            machineStore,
            new InMemorySecretStore(),
            CancellationToken.None);

        Assert.False(result.StagedFromUserScope);
        Assert.Equal(0, machineStore.SaveCount);
    }

    [Fact]
    public async Task PrepareRegistrationForInstallAsync_FailsWhenNoCompleteRegistrationExists()
    {
        var userStore = new ThrowingLoadSecretStore();
        var machineStore = new InMemorySecretStore(
            new AgentIdentity("agent-id", "tenant-id"),
            refreshToken: "",
            privateKeyPem: "private-key",
            backendUrl: "http://backend.local");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => AgentServiceProvisioning.PrepareRegistrationForInstallAsync(
                userStore,
                machineStore,
                new InMemorySecretStore(),
                CancellationToken.None));
    }

    [Fact]
    public void AgentClaimGate_IsClaimed_RequiresClaimedStateAndNoClaimRequired()
    {
        Assert.True(AgentClaimGate.IsClaimed(Heartbeat(claimRequired: false, registrationState: "claimed")));
        Assert.False(AgentClaimGate.IsClaimed(Heartbeat(claimRequired: true, registrationState: "claimed")));
        Assert.False(AgentClaimGate.IsClaimed(Heartbeat(claimRequired: true, registrationState: "pending_claim")));
        Assert.False(AgentClaimGate.IsClaimed(Heartbeat(claimRequired: false, registrationState: "deactivated")));
    }

    [Fact]
    public void AgentClaimGate_TreatsRateLimitAsTransientDuringClaimPolling()
    {
        Assert.True(AgentClaimGate.IsTransientClaimPollStatus(System.Net.HttpStatusCode.TooManyRequests));
        Assert.True(AgentClaimGate.IsTransientClaimPollStatus(System.Net.HttpStatusCode.ServiceUnavailable));
        Assert.False(AgentClaimGate.IsTransientClaimPollStatus(System.Net.HttpStatusCode.Conflict));
        Assert.False(AgentClaimGate.IsTransientClaimPollStatus(System.Net.HttpStatusCode.Forbidden));
    }

    private static HeartbeatResponse Heartbeat(bool claimRequired, string registrationState) => new(
        PendingCommands: Array.Empty<AgentCommand>(),
        NextPollSeconds: 5,
        ServerTime: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        ServerTimeUtc: DateTimeOffset.UtcNow.ToString("O"),
        CommandBatchSize: 0,
        NextSnapshotSeconds: 60,
        ConfigVersion: null,
        LifecycleState: "connected",
        RegistrationState: registrationState,
        ClaimRequired: claimRequired,
        ManifestVersion: null,
        ManagedAccountManifestHash: null,
        ManifestFreshUntil: null,
        RequireManifestBeforeUnlock: true,
        AgentStatus: registrationState,
        VersionPolicy: null,
        Update: null,
        Revoke: null,
        Quarantine: null);

    private sealed class InMemorySecretStore : ISecretStore
    {
        private AgentIdentity _identity;
        private string _refreshToken;
        private string _privateKeyPem;
        private string _backendUrl;
        private string? _tailscaleLoginServer;
        private string? _tailscaleAuthkey;

        public InMemorySecretStore()
            : this(new AgentIdentity("agent-id", "tenant-id"), "refresh-token", "private-key", "http://backend.local")
        {
        }

        public InMemorySecretStore(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer = null,
            string? tailscaleAuthkey = null)
        {
            _identity = identity;
            _refreshToken = refreshToken;
            _privateKeyPem = privateKeyPem;
            _backendUrl = backendUrl;
            _tailscaleLoginServer = tailscaleLoginServer;
            _tailscaleAuthkey = tailscaleAuthkey;
        }

        public int SaveCount { get; private set; }
        public int ClearCount { get; private set; }

        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct)
        {
            SaveCount++;
            _identity = identity;
            _refreshToken = refreshToken;
            _privateKeyPem = privateKeyPem;
            _backendUrl = backendUrl;
            _tailscaleLoginServer = tailscaleLoginServer;
            _tailscaleAuthkey = tailscaleAuthkey;
            return Task.CompletedTask;
        }

        public Task<(
            AgentIdentity Identity,
            string RefreshToken,
            string PrivateKeyPem,
            string BackendUrl,
            string? TailscaleLoginServer,
            string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((
                _identity,
                _refreshToken,
                _privateKeyPem,
                _backendUrl,
                _tailscaleLoginServer,
                _tailscaleAuthkey));

        public Task ClearAsync(CancellationToken ct)
        {
            ClearCount++;
            _refreshToken = "";
            _privateKeyPem = "";
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingLoadSecretStore : ISecretStore
    {
        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct)
            => Task.CompletedTask;

        public Task<(
            AgentIdentity Identity,
            string RefreshToken,
            string PrivateKeyPem,
            string BackendUrl,
            string? TailscaleLoginServer,
            string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => throw new InvalidOperationException("secret store unavailable");

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class MutatingSaveSecretStore : ISecretStore
    {
        private AgentIdentity _identity = new("agent-id", "tenant-id");
        private string _refreshToken = "";
        private string _privateKeyPem = "";
        private string _backendUrl = "";
        private string? _tailscaleLoginServer;
        private string? _tailscaleAuthkey;

        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct)
        {
            _identity = identity;
            _refreshToken = refreshToken + "-tampered";
            _privateKeyPem = privateKeyPem;
            _backendUrl = backendUrl;
            _tailscaleLoginServer = tailscaleLoginServer;
            _tailscaleAuthkey = tailscaleAuthkey;
            return Task.CompletedTask;
        }

        public Task<(
            AgentIdentity Identity,
            string RefreshToken,
            string PrivateKeyPem,
            string BackendUrl,
            string? TailscaleLoginServer,
            string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((
                _identity,
                _refreshToken,
                _privateKeyPem,
                _backendUrl,
                _tailscaleLoginServer,
                _tailscaleAuthkey));

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
