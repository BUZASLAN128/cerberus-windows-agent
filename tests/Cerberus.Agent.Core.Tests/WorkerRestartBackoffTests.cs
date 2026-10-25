using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

// Unit evidence for the supervisor's restart delay; the ServiceMode loop that applies it is not covered here.
public sealed class WorkerRestartBackoffTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 25, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ShortUnplannedRuns_DoubleTheDelayUpToTheCap()
    {
        var backoff = new WorkerRestartBackoff();
        Assert.True(backoff.CanStart(T0));

        var now = T0;
        var gaps = new List<TimeSpan>();
        for (var i = 0; i < 10; i++)
        {
            backoff.OnWorkerEnded(now, now.AddSeconds(1), planned: false);
            now = now.AddSeconds(1);
            var wait = TimeSpan.Zero;
            while (!backoff.CanStart(now + wait))
                wait += TimeSpan.FromSeconds(1);
            gaps.Add(wait);
            now += wait;
        }

        Assert.Equal(TimeSpan.FromSeconds(2), gaps[0]);
        Assert.Equal(TimeSpan.FromSeconds(4), gaps[1]);
        Assert.Equal(TimeSpan.FromSeconds(8), gaps[2]);
        Assert.All(gaps, g => Assert.True(g <= WorkerRestartBackoff.MaxDelay));
        Assert.Equal(WorkerRestartBackoff.MaxDelay, gaps[^1]);
    }

    [Fact]
    public void AHealthyRun_ResetsTheDelay()
    {
        var backoff = new WorkerRestartBackoff();
        var now = T0;
        for (var i = 0; i < 4; i++)
        {
            backoff.OnWorkerEnded(now, now.AddSeconds(1), planned: false);
            now = now.AddMinutes(10);
        }

        backoff.OnWorkerEnded(now, now + WorkerRestartBackoff.HealthyRun, planned: false);
        now += WorkerRestartBackoff.HealthyRun;
        Assert.True(backoff.CanStart(now));
        backoff.OnWorkerEnded(now, now.AddSeconds(1), planned: false);

        Assert.False(backoff.CanStart(now.AddSeconds(2)));
        Assert.True(backoff.CanStart(now.AddSeconds(1) + WorkerRestartBackoff.InitialDelay));
    }

    [Fact]
    public void AWorkerStoppedOnPurpose_RestartsAtOnce()
    {
        var backoff = new WorkerRestartBackoff();

        backoff.OnWorkerEnded(T0, T0.AddSeconds(1), planned: true);

        Assert.True(backoff.CanStart(T0.AddSeconds(1)));
    }
}
