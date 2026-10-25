// Dormant recovery runner (DormantStateRecovery.RunAsync) and its probe fence. Runs in both builds.
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class DormantStateRecoveryTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-06-02T00:00:00Z");

    [Fact]
    public async Task Recovery_FirstObservation_SchedulesFirstProbeWithoutProbing()
    {
        var (store, probes, run) = Harness(new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect), probeResult: true);

        var after = await run();

        Assert.Equal(0, probes.Count);
        Assert.Equal(AgentLifecycleState.AuthSuspect, after.State);
        Assert.Equal(Now + TimeSpan.FromMinutes(15), after.NextAttemptUtc);
        Assert.Equal(Now + TimeSpan.FromMinutes(15), (await store.LoadAsync(default)).NextAttemptUtc);
    }

    [Fact]
    public async Task Recovery_NotDue_DoesNotProbe()
    {
        var (_, probes, run) = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.BlockedConfig, NextAttemptUtc: Now.AddMinutes(1)), probeResult: true);

        var after = await run();

        Assert.Equal(0, probes.Count);
        Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
    }

    [Fact]
    public async Task Recovery_FailedProbe_PersistsLongerBackoffAndStaysDormant()
    {
        var (store, probes, run) = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.NeedsReenrollment, NextAttemptUtc: Now.AddSeconds(-1)),
            probeResult: false);

        var first = await run();
        Assert.Equal(1, probes.Count);
        Assert.Equal(AgentLifecycleState.NeedsReenrollment, first.State);
        Assert.Equal(1, first.TransientFailureCount);
        Assert.Equal(Now + TimeSpan.FromMinutes(30), first.NextAttemptUtc);
        Assert.Equal(first.NextAttemptUtc, (await store.LoadAsync(default)).NextAttemptUtc);
    }

    [Fact]
    public async Task Recovery_ThrowingProbe_IsTreatedAsFailure()
    {
        var (_, probes, run) = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)),
            probeResult: false, probeError: new HttpRequestException("probe"));

        var after = await run();

        Assert.Equal(1, probes.Count);
        Assert.Equal(AgentLifecycleState.AuthSuspect, after.State);
        Assert.Equal(1, after.TransientFailureCount);
    }

    [Theory]
    [InlineData(AgentLifecycleState.NeedsReenrollment)]
    [InlineData(AgentLifecycleState.AuthSuspect)]
    [InlineData(AgentLifecycleState.BlockedConfig)]
    public async Task Recovery_SuccessfulProbe_ReturnsToActiveAndClearsSchedule(AgentLifecycleState state)
    {
        var (store, probes, run) = Harness(
            new AgentLifecycleSnapshot(state, NextAttemptUtc: Now.AddSeconds(-1)) { TransientFailureCount = 3 },
            probeResult: true);

        var after = await run();

        Assert.Equal(1, probes.Count);
        Assert.Equal(AgentLifecycleState.Active, after.State);
        Assert.Null(after.NextAttemptUtc);
        Assert.Equal(0, after.TransientFailureCount);
        Assert.Equal(AgentLifecycleState.Active, (await store.LoadAsync(default)).State);
    }

    [Theory]
    [InlineData(AgentLifecycleState.Retired, null)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_deactivated")]
    [InlineData(AgentLifecycleState.AuthSuspect, "agent_revoked")]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required")]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_missing")]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_unavailable")]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_invalid")]
    [InlineData(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch")]
    [InlineData(AgentLifecycleState.BlockedConfig, "backend_url_invalid")]
    [InlineData(AgentLifecycleState.Active, null)]
    public async Task Recovery_TerminalLocalBlockOrActiveStates_NeverProbeNorSchedule(AgentLifecycleState state, string? reason)
    {
        var initial = new AgentLifecycleSnapshot(state, reason, NextAttemptUtc: Now.AddSeconds(-1));
        var (store, probes, run) = Harness(initial, probeResult: true);

        var after = await run();

        Assert.Equal(0, probes.Count);
        Assert.Equal(state, after.State);
        Assert.Equal(initial.NextAttemptUtc, (await store.LoadAsync(default)).NextAttemptUtc);
    }

    [Fact]
    public async Task Recovery_PendingQuiescenceOrAdoption_DoesNotProbe()
    {
        var pending = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)) { QuiescenceComplete = false },
            probeResult: true);
        await pending.Run();
        Assert.Equal(0, pending.Probes.Count);

        var adopting = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)),
            probeResult: true, awaitingAdoption: true);
        await adopting.Run();
        Assert.Equal(0, adopting.Probes.Count);
    }

    [Fact]
    public async Task Recovery_ScheduledCompletion_IgnoresChangedGeneration()
    {
        var store = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.NeedsReenrollment));
        var controller = new AgentLifecycleController(store);

        var result = await controller.CompleteScheduledRecoveryAsync(expectedGeneration: 99, default);

        Assert.Equal(AgentLifecycleState.NeedsReenrollment, result.State);
    }

    [Fact]
    public async Task Recovery_BlockedConfigWithoutReason_IsStillProbed()
    {
        var (_, probes, run) = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.BlockedConfig, null, NextAttemptUtc: Now.AddSeconds(-1)),
            probeResult: true);

        var after = await run();

        Assert.Equal(1, probes.Count);
        Assert.Equal(AgentLifecycleState.Active, after.State);
    }

    [Fact]
    public async Task Recovery_ProbeTimeoutWhileNotCancelled_IsAFailedProbeNotAnException()
    {
        var due = Now.AddSeconds(-1);
        var (store, probes, run) = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: due),
            probeResult: false, probeError: new TaskCanceledException("timeout", new TimeoutException()));

        var after = await run();

        Assert.Equal(1, probes.Count);
        Assert.Equal(AgentLifecycleState.AuthSuspect, after.State);
        Assert.Equal(1, after.TransientFailureCount);
        Assert.Equal(Now + TimeSpan.FromMinutes(30), after.NextAttemptUtc);
        Assert.True(after.NextAttemptUtc > due);
        Assert.Equal(after.NextAttemptUtc, (await store.LoadAsync(default)).NextAttemptUtc);
    }

    [Fact]
    public async Task Recovery_ShutdownCancellationDuringProbe_Propagates()
    {
        var store = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await DormantStateRecovery.RunAsync(store, new AgentLifecycleController(store),
                new AgentDormantRecoveryPolicy(() => Now, () => 1d),
                (_, ct) => { ct.ThrowIfCancellationRequested(); return Task.FromResult(true); },
                await store.LoadAsync(default), awaitingAdoption: false, NullAgentLogger.Instance, cts.Token));

        var stored = await store.LoadAsync(default);
        Assert.Equal(AgentLifecycleState.AuthSuspect, stored.State);
        Assert.Equal(0, stored.TransientFailureCount);
    }

    // ---- Probe answers are recorded durably, under the generation fence -----------------

    [Theory]
    [InlineData(AgentLifecycleState.Retired, "agent_revoked", false)]
    [InlineData(AgentLifecycleState.Retired, "agent_deactivated", true)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required", false)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "credentials_missing", true)]
    public async Task Recovery_ProbeSeesTerminalReenrollOrCredentialAnswer_RecordsItDurablyAndStopsProbing(
        AgentLifecycleState answerState, string answerReason, bool throwAfterAnswer)
    {
        var durable = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)));
        var probes = 0;
        var policy = new AgentDormantRecoveryPolicy(() => Now, () => 1d);
        async Task<bool> Probe(IAgentLifecycleStateStore probeState, CancellationToken ct)
        {
            probes++;
            await probeState.TransitionAsync(answerState, answerReason, "req-1", null, null, ct);
            return throwAfterAnswer ? throw new HttpRequestException("after answer") : false;
        }

        var after = await DormantStateRecovery.RunAsync(durable, new AgentLifecycleController(durable), policy, Probe,
            await durable.LoadAsync(default), awaitingAdoption: false, NullAgentLogger.Instance, default);

        var stored = await durable.LoadAsync(default);
        Assert.Equal(answerState, after.State);
        Assert.Equal(answerState, stored.State);
        Assert.Equal(answerReason, stored.ReasonCode);
        Assert.False(AgentDormantRecoveryPolicy.IsRecoverable(stored));

        await DormantStateRecovery.RunAsync(durable, new AgentLifecycleController(durable), policy, Probe,
            stored, awaitingAdoption: false, NullAgentLogger.Instance, default);
        Assert.Equal(1, probes);
    }

    [Fact]
    public async Task Recovery_ProbeAnswerForSupersededGeneration_IsDropped()
    {
        var durable = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)));

        await DormantStateRecovery.RunAsync(durable, new AgentLifecycleController(durable),
            new AgentDormantRecoveryPolicy(() => Now, () => 1d),
            async (probeState, ct) =>
            {
                // An enrollment adoption commits (dormant to Active, new generation) while the heartbeat is in flight.
                var current = await durable.LoadAsync(ct);
                await durable.SaveAsync(current with { State = AgentLifecycleState.Active, ReasonCode = null, NextAttemptUtc = null }, ct);
                await probeState.TransitionAsync(AgentLifecycleState.Retired, "agent_revoked", null, null, null, ct);
                return false;
            },
            await durable.LoadAsync(default), awaitingAdoption: false, NullAgentLogger.Instance, default);

        var stored = await durable.LoadAsync(default);
        Assert.Equal(AgentLifecycleState.Active, stored.State);
        Assert.Null(stored.ReasonCode);
    }

    [Fact]
    public async Task ProbeFence_BumpedGenerationBetweenLoadAndSave_LeavesSecretsByteIdentical()
    {
        var (secrets, path) = await RegisteredAsync();
        var (durable, fenced, probeSecrets) = await FenceAsync(secrets);
        var loaded = await probeSecrets.LoadAsync(default);
        var scratch = await fenced.LoadAsync(default);
        var current = await durable.LoadAsync(default);
        await durable.TrySaveAsync(current with { Generation = current.Generation + 1 }, current.Revision, default);
        var before = File.ReadAllBytes(path);

        var ran = await fenced.ExecuteIfCurrentAsync(scratch.Generation, ct => probeSecrets.SaveAsync(
            loaded.Identity, "rotated-token", loaded.PrivateKeyPem, loaded.BackendUrl, null, null, ct), default);

        Assert.False(ran);
        Assert.Equal(before, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task ProbeFence_CurrentGeneration_AppliesTokenRotation()
    {
        var (secrets, _) = await RegisteredAsync();
        var (_, fenced, probeSecrets) = await FenceAsync(secrets);
        var loaded = await probeSecrets.LoadAsync(default);
        var scratch = await fenced.LoadAsync(default);

        var ran = await fenced.ExecuteIfCurrentAsync(scratch.Generation, ct => probeSecrets.SaveAsync(
            loaded.Identity, "rotated-token", loaded.PrivateKeyPem, loaded.BackendUrl, null, null, ct), default);

        Assert.True(ran);
        Assert.Equal("rotated-token", (await secrets.LoadAsync(default)).RefreshToken);
    }

    [Fact]
    public async Task ProbeFence_WriteOutsideFenceAndClear_AreRefusedAndKeepSecrets()
    {
        var (secrets, path) = await RegisteredAsync();
        var (_, _, probeSecrets) = await FenceAsync(secrets);
        var before = File.ReadAllBytes(path);

        await Assert.ThrowsAsync<InvalidOperationException>(() => probeSecrets.SaveAsync(
            new AgentIdentity("x", "y"), "t", "k", "https://x.example.test", null, null, default));
        await Assert.ThrowsAsync<InvalidOperationException>(() => probeSecrets.ClearAsync(default));

        Assert.Equal(before, File.ReadAllBytes(path));
    }

    [Fact]
    public async Task Recovery_AdoptionDuringProbe_KeepsAdoptedIdentity()
    {
        var (secrets, _) = await RegisteredAsync();
        var durable = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)));

        await DormantStateRecovery.RunAsync(durable, new AgentLifecycleController(durable),
            new AgentDormantRecoveryPolicy(() => Now, () => 1d),
            async (probeState, ct) =>
            {
                var probeSecrets = new RecoveryProbeSecretStore(secrets, (FencedProbeLifecycleStore)probeState);
                var old = await probeSecrets.LoadAsync(ct);
                // enrollment-adopt publishes the new identity and moves the generation during the heartbeat
                await secrets.SaveAsync(new AgentIdentity("agent-id-2", "tenant-id-1"), "refresh-2", "key-pem-2", old.BackendUrl, null, null, ct);
                var current = await durable.LoadAsync(ct);
                await durable.SaveAsync(current with { State = AgentLifecycleState.Active, ReasonCode = null, NextAttemptUtc = null }, ct);
                // the old identity's token rotation then arrives
                var scratch = await probeState.LoadAsync(ct);
                await probeState.ExecuteIfCurrentAsync(scratch.Generation, c => probeSecrets.SaveAsync(
                    old.Identity, "refresh-rotated", old.PrivateKeyPem, old.BackendUrl, null, null, c), ct);
                return true;
            },
            await durable.LoadAsync(default), awaitingAdoption: false, NullAgentLogger.Instance, default);

        var creds = await secrets.LoadAsync(default);
        Assert.Equal(new AgentIdentity("agent-id-2", "tenant-id-1"), creds.Identity);
        Assert.Equal("refresh-2", creds.RefreshToken);
        Assert.Equal("key-pem-2", creds.PrivateKeyPem);
        Assert.Equal(AgentLifecycleState.Active, (await durable.LoadAsync(default)).State);
    }

    private static async Task<(DpapiSecretStore Secrets, string Path)> RegisteredAsync()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var secrets = new DpapiSecretStore(SecretStoreScope.User, dir);
        await secrets.SaveAsync(new AgentIdentity("agent-id-1", "tenant-id-1"), "refresh-1", "key-pem-1",
            "https://old-collector.example.test:8443", null, null, default);
        return (secrets, Path.Combine(dir, "secrets.json"));
    }

    private static async Task<(InMemoryAgentLifecycleStateStore Durable, FencedProbeLifecycleStore Fenced, RecoveryProbeSecretStore Secrets)>
        FenceAsync(DpapiSecretStore secrets)
    {
        var durable = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)));
        var fenced = new FencedProbeLifecycleStore(durable, (await durable.LoadAsync(default)).Generation);
        return (durable, fenced, new RecoveryProbeSecretStore(secrets, fenced));
    }

    private static (InMemoryAgentLifecycleStateStore Store, ProbeCounter Probes, Func<Task<AgentLifecycleSnapshot>> Run) Harness(
        AgentLifecycleSnapshot initial, bool probeResult, Exception? probeError = null, bool awaitingAdoption = false)
    {
        var store = new InMemoryAgentLifecycleStateStore(initial);
        var probes = new ProbeCounter();
        var policy = new AgentDormantRecoveryPolicy(() => Now, () => 1d);
        var controller = new AgentLifecycleController(store);
        async Task<AgentLifecycleSnapshot> Run()
        {
            var snapshot = await store.LoadAsync(default);
            return await DormantStateRecovery.RunAsync(store, controller, policy,
                (_, _) =>
                {
                    probes.Count++;
                    return probeError is not null ? throw probeError : Task.FromResult(probeResult);
                },
                snapshot, awaitingAdoption, NullAgentLogger.Instance, default);
        }
        return (store, probes, Run);
    }

    private sealed class ProbeCounter { public int Count; }
}
