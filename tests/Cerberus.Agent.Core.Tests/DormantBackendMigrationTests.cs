// Backend address migration (DormantStateRecovery.TryMigrateBackendAsync). The compiled address is
// passed through the optional parameter; the positive cases need the server profile, the negative
// cases run with an eligible input so each guard is the only thing that can refuse.
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

[Collection("BackendUrlEnvironment")]
public sealed class DormantBackendMigrationTests
{
    private const string OldBackend = "https://old-collector.example.test:8443";
    private const string Compiled = "https://new-collector.example.test:8443";

    private static async Task WithOverrideAsync(string? value, Func<Task> body)
    {
        var saved = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL");
        Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", value);
        try { await body(); }
        finally { Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", saved); }
    }

    private static InMemoryAgentLifecycleStateStore StoreWith(AgentLifecycleState state, string? reason, bool quiescent = true)
        => new(new AgentLifecycleSnapshot(state, reason) { QuiescenceComplete = quiescent });

    [Fact]
    public async Task Migration_CompiledHttpAddress_StaysDormantWithRegistrationUnchanged()
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch");
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption: false, NullAgentLogger.Instance, default, "http://new-collector.example.test:8080");

            Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
            Assert.Equal(AgentLifecycleState.BlockedConfig, (await store.LoadAsync(default)).State);
            Assert.Equal(OldBackend, secrets.BackendUrl);
        });
    }

    [Fact]
    public async Task Migration_EnvironmentOverride_StaysDormantWithRegistrationUnchanged()
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch");
        await WithOverrideAsync("https://override.example.test", async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
            Assert.Equal(AgentLifecycleState.BlockedConfig, (await store.LoadAsync(default)).State);
            Assert.Equal(OldBackend, secrets.BackendUrl);
        });
    }

#if CERBERUS_SERVER_PROFILE
    [Fact]
    public async Task Migration_CompiledHttpsAddressAndNoOverride_ActivatesAndKeepsIdentity()
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch");
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            Assert.Equal(AgentLifecycleState.Active, after.State);
            Assert.Equal(AgentLifecycleState.Active, (await store.LoadAsync(default)).State);
            AssertMigratedKeepingCredentials(await secrets.LoadAsync(default));
        });
    }

    [Fact]
    public async Task Migration_MismatchBlockAlreadyAtCompiledAddress_ReturnsToActive()
    {
        var secrets = new MemorySecretStore(Compiled);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch");
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            Assert.Equal(AgentLifecycleState.Active, after.State);
            Assert.Equal(0, secrets.Saves);
        });
    }

    [Theory]
    [InlineData(AgentLifecycleState.AuthSuspect, null)]
    [InlineData(AgentLifecycleState.AuthSuspect, "auth_suspect")]
    [InlineData(AgentLifecycleState.AuthSuspect, "backend_environment_mismatch")]
    [InlineData(AgentLifecycleState.BlockedConfig, "some_other_block")]
    [InlineData(AgentLifecycleState.BlockedConfig, "backend_url_invalid")]
    [InlineData(AgentLifecycleState.NeedsReenrollment, null)]
    public async Task Migration_FromNonMismatchDormantState_MovesAddressAndKeepsState(AgentLifecycleState state, string? reason)
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(state, reason);
        var before = await store.LoadAsync(default);
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, before,
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            var stored = await store.LoadAsync(default);
            Assert.Equal(state, after.State);
            Assert.Equal(reason, after.ReasonCode);
            Assert.Equal(state, stored.State);
            Assert.Equal(reason, stored.ReasonCode);
            Assert.Equal(before.Generation, stored.Generation);
            AssertMigratedKeepingCredentials(await secrets.LoadAsync(default));
        });
    }

    [Theory]
    [InlineData(AgentLifecycleState.Retired, null, false, true)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_deactivated", false, true)]
    [InlineData(AgentLifecycleState.AuthSuspect, "agent_revoked", false, true)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required", false, true)]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_invalid", false, true)]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_unavailable", false, true)]
    [InlineData(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch", true, true)]
    [InlineData(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch", false, false)]
    [InlineData(AgentLifecycleState.Active, null, false, true)]
    [InlineData(AgentLifecycleState.Degraded, null, false, true)]
    public async Task Migration_EachGuardRefusesOtherwiseEligibleInput(
        AgentLifecycleState state, string? reason, bool awaitingAdoption, bool quiescent)
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(state, reason, quiescent);
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption, NullAgentLogger.Instance, default, Compiled);

            Assert.Equal(state, after.State);
            Assert.Equal(state, (await store.LoadAsync(default)).State);
            Assert.Equal(OldBackend, secrets.BackendUrl);
            Assert.Equal(0, secrets.Saves);
        });
    }

    [Fact]
    public async Task Migration_GenerationChangedSinceObserved_LeavesRegistrationUnchanged()
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(AgentLifecycleState.AuthSuspect, null);
        var observed = await store.LoadAsync(default);
        await store.TrySaveAsync(observed with { Generation = observed.Generation + 1 }, observed.Revision, default);
        await WithOverrideAsync(null, async () =>
        {
            await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, observed,
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            Assert.Equal(OldBackend, secrets.BackendUrl);
            Assert.Equal(0, secrets.Saves);
        });
    }

    private static void AssertMigratedKeepingCredentials(
        (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey) creds)
    {
        Assert.Equal(Compiled, creds.BackendUrl);
        Assert.Equal(new AgentIdentity("agent-id-1", "tenant-id-1"), creds.Identity);
        Assert.Equal("refresh-1", creds.RefreshToken);
        Assert.Equal("key-pem-1", creds.PrivateKeyPem);
    }
#else
    [Fact]
    public async Task Migration_DefaultBuild_NeverChangesRegistrationOrState()
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch");
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
            Assert.Equal(OldBackend, secrets.BackendUrl);
            Assert.Equal(0, secrets.Saves);
        });
    }
#endif
}
