// Supervisor step of the server-profile service loop (DormantRecoverySupervisor): in-process
// throttling, mismatch-block handling and the recovery schedule. The type is compiled in both
// builds; the service creates it only in the server profile.
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

[Collection("BackendUrlEnvironment")]
public sealed class DormantRecoverySupervisorTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-06-02T00:00:00Z");
    private static readonly TimeSpan LoopTick = TimeSpan.FromSeconds(2);
    private const string OldBackend = "https://old-collector.example.test:8443";

    [Fact]
    public async Task Supervisor_DurableWritesKeepFailing_ProbesAtMostOncePerInterval()
    {
        var clock = Now;
        var store = new FailingSaveLifecycleStore(new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect));
        var log = new CountingLogger();
        var probes = 0;
        var supervisor = Create(store, new MemorySecretStore(OldBackend), log, () => clock,
            probe: (_, _) => { probes++; return Task.FromResult(false); });

        // First observation writes the schedule (due in 15 min); every later durable write throws.
        var scheduled = await supervisor.TickAsync(await store.LoadAsync(default), false, default);
        Assert.Equal(Now + TimeSpan.FromMinutes(15), scheduled.NextAttemptUtc);
        store.FailSaves = true;

        var start = Now + TimeSpan.FromMinutes(15);
        for (var elapsed = TimeSpan.Zero; elapsed <= TimeSpan.FromMinutes(25); elapsed += LoopTick)
        {
            clock = start + elapsed;
            await supervisor.TickAsync(await store.LoadAsync(default), false, default);
        }

        Assert.Equal(3, probes);
        Assert.InRange(log.Warnings, 1, 3);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Supervisor_MismatchBlockThatCannotMigrate_IsNeverProbedAndReadsCredentialsOncePerInterval(bool credentialsUnreadable)
    {
        // An environment override makes the compiled address ineligible in both builds (ShouldMigrate is false).
        var saved = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL");
        Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", "https://override.example.test");
        try
        {
            var clock = Now;
            var blocked = new AgentLifecycleSnapshot(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch",
                NextAttemptUtc: Now.AddSeconds(-1));
            var store = new FailingSaveLifecycleStore(blocked);
            var secrets = new MemorySecretStore(OldBackend) { LoadError = credentialsUnreadable ? new IOException("unreadable") : null };
            var log = new CountingLogger();
            var probes = 0;
            var supervisor = Create(store, secrets, log, () => clock, probe: (_, _) => { probes++; return Task.FromResult(true); });

            for (var elapsed = TimeSpan.Zero; elapsed <= TimeSpan.FromMinutes(25); elapsed += LoopTick)
            {
                clock = Now + elapsed;
                await supervisor.TickAsync(await store.LoadAsync(default), false, default);
            }

            var stored = await store.LoadAsync(default);
            Assert.Equal(0, probes);
            Assert.Equal(3, secrets.Loads);
            Assert.Equal(0, secrets.Saves);
            Assert.Equal(AgentLifecycleState.BlockedConfig, stored.State);
            Assert.Equal("backend_environment_mismatch", stored.ReasonCode);
            Assert.Equal(OldBackend, secrets.BackendUrl);
            Assert.True(log.Warnings <= 3);
        }
        finally { Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", saved); }
    }

    [Theory]
    [InlineData(-1, 5)]
    [InlineData(6 * 60 * 60, 5)]
    public async Task Supervisor_FirstDelayIgnoresCarriedRetryFields(int carriedOffsetSeconds, int carriedCount)
    {
        var store = new FailingSaveLifecycleStore(new AgentLifecycleSnapshot(
            AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(carriedOffsetSeconds)) { TransientFailureCount = carriedCount });
        var probes = 0;
        var supervisor = Create(store, new MemorySecretStore(OldBackend), new CountingLogger(), () => Now,
            probe: (_, _) => { probes++; return Task.FromResult(false); });

        var after = await supervisor.TickAsync(await store.LoadAsync(default), false, default);

        Assert.Equal(0, probes);
        Assert.Equal(Now + AgentDormantRecoveryPolicy.InitialDelay, after.NextAttemptUtc);
        Assert.Equal(0, after.TransientFailureCount);
        Assert.Equal(after.NextAttemptUtc, (await store.LoadAsync(default)).NextAttemptUtc);
    }

    [Fact]
    public async Task Supervisor_BusyManualGate_SkipsTheTickWithoutUsingUpTheWindow()
    {
        var store = new FailingSaveLifecycleStore(new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect));
        var gate = new SemaphoreSlim(1, 1);
        var supervisor = Create(store, new MemorySecretStore(OldBackend), new CountingLogger(), () => Now, gate: gate);

        await gate.WaitAsync();
        var busy = await supervisor.TickAsync(await store.LoadAsync(default), false, default);
        gate.Release();
        var free = await supervisor.TickAsync(await store.LoadAsync(default), false, default);

        Assert.Null(busy.NextAttemptUtc);
        Assert.Equal(Now + AgentDormantRecoveryPolicy.InitialDelay, free.NextAttemptUtc);
    }

    // ---- Manual retry keeps the transient-retry deferral outside the dormant recovery schedule ----

    [Fact]
    public async Task ManualRetry_NonDormantStateWithFutureRetryTime_IsStillDeferred()
    {
        var store = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.Degraded, NextAttemptUtc: DateTimeOffset.UtcNow.AddHours(1)));
        var service = new AgentLocalControlService(store, _ => Task.CompletedTask);

        var response = await service.HandleAsync(new AgentLocalControlRequest("retry"), default);

        Assert.False(response.Success);
        Assert.Equal("retry_deferred", response.Code);
    }

#if !CERBERUS_SERVER_PROFILE
    [Fact]
    public async Task ManualRetry_DefaultBuild_DormantStateWithFutureRetryTime_IsDeferred()
    {
        var store = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: DateTimeOffset.UtcNow.AddHours(1)));
        var service = new AgentLocalControlService(store, _ => Task.CompletedTask);

        var response = await service.HandleAsync(new AgentLocalControlRequest("retry"), default);

        Assert.Equal("retry_deferred", response.Code);
    }
#endif

    private static DormantRecoverySupervisor Create(
        IAgentLifecycleStateStore store, ISecretStore secrets, IAgentLogger log, Func<DateTimeOffset> clock,
        Func<IAgentLifecycleStateStore, CancellationToken, Task<bool>>? probe = null, SemaphoreSlim? gate = null)
        => new(store, new AgentLifecycleController(store), secrets, gate ?? new SemaphoreSlim(1, 1), log,
            new AgentDormantRecoveryPolicy(clock, () => 1d), probe ?? ((_, _) => Task.FromResult(false)), clock);
}
