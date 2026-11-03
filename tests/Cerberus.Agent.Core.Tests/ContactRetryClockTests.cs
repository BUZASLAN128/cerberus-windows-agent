using Cerberus.Agent.App;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using System.Text.Json;

namespace Cerberus.Agent.Core.Tests;

// UTC can move backwards while elapsed time and timers continue forwards.
internal sealed class ContactRetryClock : TimeProvider
{
    private readonly FakeTime _inner = new(1_780_358_400);
    public TimeSpan UtcOffset { get; set; }
    public int ActiveTimerCount => _inner.ActiveTimerCount;
    public override DateTimeOffset GetUtcNow() => _inner.GetUtcNow() + UtcOffset;
    public override long GetTimestamp() => _inner.GetTimestamp();
    public override long TimestampFrequency => _inner.TimestampFrequency;
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        => _inner.CreateTimer(callback, state, dueTime, period);
    public void Advance(TimeSpan elapsed) => _inner.Advance(elapsed);
}

[Collection("BackendUrlEnvironment")]
public sealed class ContactRetryClockTests
{
    [Fact]
    public void OldDurableRecoveryDeadline_RemainsBoundedAfterUtcRollback()
    {
        var clock = new ContactRetryClock();
        var policy = new AgentDormantRecoveryPolicy(clock.GetUtcNow, () => 1d, clock);
        var old = new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect,
            NextAttemptUtc: clock.GetUtcNow().AddHours(6));
        Assert.False(policy.IsDue(old));
        clock.UtcOffset = -TimeSpan.FromHours(1);
        clock.Advance(TimeSpan.FromSeconds(AgentTimingPolicy.Current.Bounds.PollCeiling - 1));
        Assert.False(policy.IsDue(old));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True(policy.IsDue(old));
        Assert.False(AgentDormantRecoveryPolicy.IsRecoverable(old with { State = AgentLifecycleState.Retired }));
        Assert.False(AgentDormantRecoveryPolicy.IsRecoverable(old with { ReasonCode = "credentials_missing" }));
    }

    [Theory]
    [InlineData(0d, 45)]
    [InlineData(1d, 60)]
    public async Task SupervisorThrottle_PreservesJitterAndElapsedDeadlineAfterUtcRollback(double jitter, int expectedSeconds)
    {
        var clock = new ContactRetryClock();
        var store = new InMemoryAgentLifecycleStateStore(new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect));
        var probes = 0;
        var policy = new AgentDormantRecoveryPolicy(clock.GetUtcNow, () => jitter, clock);
        using var gate = new SemaphoreSlim(1, 1);
        var supervisor = new DormantRecoverySupervisor(store, new AgentLifecycleController(store),
            new MemorySecretStore("https://collector.example.test"), gate, new CountingLogger(), policy,
            (_, _) => { probes++; return Task.FromResult(false); }, clock.GetUtcNow, clock);
        var scheduled = await supervisor.TickAsync(await store.LoadAsync(default), false, default);
        Assert.Equal(clock.GetUtcNow().AddSeconds(expectedSeconds), scheduled.NextAttemptUtc);
        clock.UtcOffset = -TimeSpan.FromHours(1);
        clock.Advance(TimeSpan.FromSeconds(expectedSeconds - 1));
        await supervisor.TickAsync(await store.LoadAsync(default), false, default);
        Assert.Equal(0, probes);
        clock.Advance(TimeSpan.FromSeconds(1));
        await supervisor.TickAsync(await store.LoadAsync(default), false, default);
        Assert.Equal(1, probes);
    }

    [Fact]
    public void WorkerRestartDeadline_UsesElapsedTimeAfterUtcRollback()
    {
        var clock = new ContactRetryClock();
        var restart = new WorkerRestartBackoff(clock);
        for (var i = 0; i < 10; i++) restart.OnWorkerEnded(clock.GetUtcNow().AddSeconds(-1), clock.GetUtcNow(), false);
        clock.UtcOffset = -TimeSpan.FromHours(1);
        Assert.False(restart.CanStart(clock.GetUtcNow()));
        clock.Advance(WorkerRestartBackoff.MaxDelay - TimeSpan.FromSeconds(1));
        Assert.False(restart.CanStart(clock.GetUtcNow()));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.True(restart.CanStart(clock.GetUtcNow()));
        Assert.InRange(WorkerRestartBackoff.MaxDelay, TimeSpan.Zero, TimeSpan.FromSeconds(AgentTimingPolicy.Current.Bounds.PollCeiling));
    }
}

public sealed partial class AgentWakeupClientTests
{
    [Fact]
    public async Task RateLimitedReconnect_UsesElapsedTimeAfterUtcRollback()
    {
        var clock = new ContactRetryClock();
        var calls = 0;
        var firstContact = clock.GetTimestamp();
        var nextContact = firstContact;
        using var http = new HttpClient { BaseAddress = new Uri("https://agent.example") };
        var api = new AgentApiClient(http, new FakeSecrets(), new FakeToken(), new FakeSigner());
        await using var client = new AgentWakeupClient(api, new AgentWakeupSignal(),
            (_, _, _, _) =>
            {
                nextContact = clock.GetTimestamp();
                Interlocked.Increment(ref calls);
                throw new WakeupRateLimitedException(TimeSpan.FromHours(1));
            }, time: clock, retryJitter: () => 1d);
        using var discovery = JsonDocument.Parse("""{"version":1,"path":"/api/ws"}""");
        await client.ConfigureAsync(discovery.RootElement, default);
        await Wait.UntilAsync(() => client.NotBefore != DateTimeOffset.MinValue && clock.ActiveTimerCount > 0, "rate-limit deadline");
        clock.UtcOffset = -TimeSpan.FromHours(1);
        clock.Advance(TimeSpan.FromSeconds(AgentTimingPolicy.Current.Bounds.PollCeiling));
        await Wait.UntilAsync(() => Volatile.Read(ref calls) >= 2, "reconnect after UTC rollback");
        Assert.InRange(clock.GetElapsedTime(firstContact, nextContact), TimeSpan.Zero,
            TimeSpan.FromSeconds(AgentTimingPolicy.Current.Bounds.PollCeiling));
        await client.ConfigureAsync(null, default);
    }
}
