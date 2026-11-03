using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentWakeupClientTests
{
    [Fact]
    public async Task FailuresSurviveQuickOpenAndReconfigurationButStableOpenResetsThem()
    {
        using var http = new HttpClient { BaseAddress = new Uri("https://agent.example") };
        var api = new AgentApiClient(http, new FakeSecrets(), new FakeToken(), new FakeSigner());
        var clock = new FakeTime(EnvelopeHarness.T0);
        var calls = 0;
        async Task Listen(JsonElement _, AgentWakeupSignal __, Action opened, CancellationToken ct)
        {
            switch (Interlocked.Increment(ref calls))
            {
                case 1: throw new IOException("controlled connection failure");
                case 2: opened(); clock.Advance(TimeSpan.FromSeconds(59)); return;
                case 3: opened(); clock.Advance(TimeSpan.FromSeconds(60)); return;
                default: await Task.Delay(Timeout.InfiniteTimeSpan, ct); return;
            }
        }
        await using var client = new AgentWakeupClient(api, new AgentWakeupSignal(), Listen, time: clock);
        using var discovery = JsonDocument.Parse("""{"version":1,"path":"/api/ws"}""");
        await client.ConfigureAsync(discovery.RootElement, default);
        Assert.Equal(1, client.ConsecutiveFailures);
        await client.ConfigureAsync(null, default);
        await client.ConfigureAsync(discovery.RootElement, default);
        await Wait.UntilAsync(() => client.ConsecutiveFailures == 2 && clock.ActiveTimerCount > 0, "quick open/backoff");
        clock.Advance(TimeSpan.FromMinutes(5));
        await Wait.UntilAsync(() => Volatile.Read(ref calls) == 3 && client.ConsecutiveFailures == 0 && clock.ActiveTimerCount > 0,
            "stable open resets failures");
    }

    [Fact]
    public async Task ExcessiveRetryAfterIsCappedAcrossHeartbeatReconfiguration()
    {
        using var http = new HttpClient { BaseAddress = new Uri("https://agent.example") };
        var api = new AgentApiClient(http, new FakeSecrets(), new FakeToken(), new FakeSigner());
        var clock = new FakeTime(EnvelopeHarness.T0);
        var calls = 0;
        Task Listen(JsonElement _, AgentWakeupSignal __, Action ___, CancellationToken ____)
        {
            Interlocked.Increment(ref calls);
            throw new WakeupRateLimitedException(TimeSpan.MaxValue);
        }
        await using var client = new AgentWakeupClient(api, new AgentWakeupSignal(), Listen, time: clock);
        using var discovery = JsonDocument.Parse("""{"version":1,"path":"/api/ws"}""");
        await client.ConfigureAsync(discovery.RootElement, default);
        Assert.Equal(clock.Now.AddSeconds(AgentTimingPolicy.Current.Bounds.PollCeiling), client.NotBefore);
        await client.ConfigureAsync(null, default);
        await client.ConfigureAsync(discovery.RootElement, default);
        clock.Advance(TimeSpan.FromSeconds(AgentTimingPolicy.Current.Bounds.PollCeiling - 1));
        Assert.Equal(1, Volatile.Read(ref calls));
        clock.Advance(TimeSpan.FromSeconds(1));
        await Wait.UntilAsync(() => Volatile.Read(ref calls) == 2, "bounded retry resumes");
    }
}
