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

    // ---- Local configuration blocks clear without a network call once the cause is gone ----

    [Theory]
    [InlineData(null)]
    [InlineData(Compiled)]
    public async Task LocalConfigBlock_UrlInvalidWithEnvironmentFixed_ReturnsToActive(string? fixedOverride)
    {
        var secrets = new MemorySecretStore(Compiled);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_url_invalid");
        await WithOverrideAsync(fixedOverride, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            var stored = await store.LoadAsync(default);
            Assert.Equal(AgentLifecycleState.Active, after.State);
            Assert.Equal(AgentLifecycleState.Active, stored.State);
            Assert.Null(stored.ReasonCode);
            Assert.Equal(Compiled, secrets.BackendUrl);
        });
    }

    [Fact]
    public async Task LocalConfigBlock_UrlInvalidWithEnvironmentStillInvalid_StaysBlocked()
    {
        var secrets = new MemorySecretStore(Compiled);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_url_invalid");
        await WithOverrideAsync("not a url", async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
            Assert.Equal("backend_url_invalid", (await store.LoadAsync(default)).ReasonCode);
        });
    }

    [Fact]
    public async Task LocalConfigBlock_UrlInvalidWithOldRegistration_MovesAddressThenReturnsToActive()
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_url_invalid");
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            Assert.Equal(AgentLifecycleState.Active, after.State);
            AssertMigratedKeepingCredentials(await secrets.LoadAsync(default));
        });
    }

    [Fact]
    public async Task LocalConfigBlock_MismatchWithOverrideRemovedAndBlankCompiledAddress_ReturnsToActive()
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch");
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, await store.LoadAsync(default),
                awaitingAdoption: false, NullAgentLogger.Instance, default, "");

            Assert.Equal(AgentLifecycleState.Active, after.State);
            Assert.Equal(OldBackend, secrets.BackendUrl);
            Assert.Equal(0, secrets.Saves);
        });
    }

    [Fact]
    public async Task LocalConfigBlock_MismatchWithHttpCompiledTarget_StaysBlockedWithoutWrites()
    {
        var secrets = new MemorySecretStore(OldBackend);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch");
        var before = await store.LoadAsync(default);
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, before,
                awaitingAdoption: false, NullAgentLogger.Instance, default, "http://new-collector.example.test:8080");

            Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
            Assert.Equal(before.Revision, (await store.LoadAsync(default)).Revision);
            Assert.Equal(0, secrets.Saves);
        });
    }

    [Fact]
    public async Task LocalConfigBlock_GenerationAlreadyChanged_WritesNothing()
    {
        var secrets = new MemorySecretStore(Compiled);
        var store = StoreWith(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch");
        var observed = await store.LoadAsync(default);
        await store.TrySaveAsync(observed with { Generation = observed.Generation + 1 }, observed.Revision, default);
        var changed = await store.LoadAsync(default);
        await WithOverrideAsync(null, async () =>
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, observed,
                awaitingAdoption: false, NullAgentLogger.Instance, default, Compiled);

            var stored = await store.LoadAsync(default);
            Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
            Assert.Equal(changed.Revision, stored.Revision);
            Assert.Equal(AgentLifecycleState.BlockedConfig, stored.State);
            Assert.Equal(0, secrets.Saves);
        });
    }

    // The change lands after the second fenced action has returned true (the address read), before the
    // local-configuration re-check reloads the snapshot.
    [Fact]
    public async Task LocalConfigBlock_GenerationChangesAfterTheAddressRead_WritesNothing()
    {
        var (store, secrets, observed, after, log) = await RunRaceAsync(c => c with { Generation = c.Generation + 1 });

        var stored = await store.LoadAsync(default);
        Assert.True(store.Changed);
        Assert.Equal(observed.Generation + 1, stored.Generation);
        Assert.Equal(AgentLifecycleState.BlockedConfig, stored.State);
        Assert.Equal("backend_environment_mismatch", stored.ReasonCode);
        Assert.Equal(stored.Revision, after.Revision);
        Assert.Equal(0, secrets.Saves);
        Assert.Empty(log.Infos);
    }

    [Fact]
    public async Task LocalConfigBlock_QuiescenceLostAfterTheAddressRead_WritesNothing()
    {
        var (store, secrets, observed, after, log) = await RunRaceAsync(c => c with { QuiescenceComplete = false });

        var stored = await store.LoadAsync(default);
        Assert.True(store.Changed);
        Assert.Equal(observed.Generation, stored.Generation);
        Assert.False(stored.QuiescenceComplete);
        Assert.Equal(AgentLifecycleState.BlockedConfig, stored.State);
        Assert.Equal("backend_environment_mismatch", stored.ReasonCode);
        Assert.Equal(stored.Revision, after.Revision);
        Assert.Equal(0, secrets.Saves);
        Assert.Empty(log.Infos);
    }

    // Every credential read of the migration happens inside the durable generation fence.
    [Fact]
    public async Task LocalConfigBlock_CredentialReadsHappenOnlyInsideTheFence()
    {
        var (store, secrets, _, after, log) = await RunRaceAsync(c => c);

        Assert.Equal(2, secrets.Loads);
        Assert.Equal(0, secrets.LoadsOutsideFence);
        Assert.Equal(2, store.FenceRuns);
        Assert.Equal(AgentLifecycleState.Active, after.State);
        Assert.Equal(new[] { "Backend configuration block 'backend_environment_mismatch' cleared; resuming." }, log.Infos);
    }

    private static async Task<(FencedRaceStore Store, FenceAwareSecretStore Secrets, AgentLifecycleSnapshot Observed,
        AgentLifecycleSnapshot After, RecordingLogger Log)> RunRaceAsync(Func<AgentLifecycleSnapshot, AgentLifecycleSnapshot> afterSecondFence)
    {
        var store = new FencedRaceStore(StoreWith(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch"), afterSecondFence);
        var secrets = new FenceAwareSecretStore(new MemorySecretStore(Compiled), store);
        var log = new RecordingLogger();
        var observed = await store.LoadAsync(default);
        AgentLifecycleSnapshot after = observed;
        await WithOverrideAsync(null, async () =>
            after = await DormantStateRecovery.TryMigrateBackendAsync(store, secrets, observed,
                awaitingAdoption: false, log, default, Compiled));
        return (store, secrets, observed, after, log);
    }

    /// <summary>
    /// Records whether a fenced action is running and applies <c>afterSecondFence</c> to the stored
    /// snapshot right after the second fenced action returned true, as a concurrent adopt, unregister
    /// or quiescence change would.
    /// </summary>
    private sealed class FencedRaceStore : IAgentLifecycleStateStore
    {
        private readonly InMemoryAgentLifecycleStateStore _inner;
        private readonly Func<AgentLifecycleSnapshot, AgentLifecycleSnapshot> _change;
        public bool Active;
        public bool Changed;
        public int FenceRuns;

        public FencedRaceStore(InMemoryAgentLifecycleStateStore inner, Func<AgentLifecycleSnapshot, AgentLifecycleSnapshot> change)
            => (_inner, _change) = (inner, change);

        public Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct) => _inner.LoadAsync(ct);
        public Task SaveAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct) => _inner.SaveAsync(snapshot, ct);
        public Task<AgentLifecycleSnapshot?> TrySaveAsync(AgentLifecycleSnapshot snapshot, long expectedRevision, CancellationToken ct)
            => _inner.TrySaveAsync(snapshot, expectedRevision, ct);

        public async Task<bool> ExecuteIfCurrentAsync(long expectedGeneration, Func<CancellationToken, Task> action, CancellationToken ct)
        {
            bool ran;
            Active = true;
            try { ran = await _inner.ExecuteIfCurrentAsync(expectedGeneration, action, ct); }
            finally { Active = false; }
            if (ran && ++FenceRuns == 2)
            {
                var current = await _inner.LoadAsync(ct);
                var changed = _change(current);
                if (!ReferenceEquals(changed, current))
                {
                    Changed = true;
                    await _inner.TrySaveAsync(changed, current.Revision, ct);
                }
            }
            return ran;
        }
    }

    private sealed class FenceAwareSecretStore : ISecretStore
    {
        private readonly MemorySecretStore _inner;
        private readonly FencedRaceStore _fence;
        public int LoadsOutsideFence;

        public FenceAwareSecretStore(MemorySecretStore inner, FencedRaceStore fence) => (_inner, _fence) = (inner, fence);

        public int Loads => _inner.Loads;
        public int Saves => _inner.Saves;

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            if (!_fence.Active)
                LoadsOutsideFence++;
            return _inner.LoadAsync(ct);
        }

        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
            => _inner.SaveAsync(identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey, ct);

        public Task ClearAsync(CancellationToken ct) => _inner.ClearAsync(ct);
    }

    private sealed class RecordingLogger : IAgentLogger
    {
        public readonly List<string> Infos = new();
        public void Info(string message) => Infos.Add(message);
        public void Warn(string message) { }
        public void Error(string message, Exception? ex = null) { }
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
