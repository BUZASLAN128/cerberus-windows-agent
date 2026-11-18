using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateWatchPolicyTests
{
    private static readonly DateTimeOffset Started = DateTimeOffset.Parse("2026-11-18T15:30:00Z");
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(2);

    [Fact]
    public void CrashCountsAreLocalToTheWatchAndBootAndACleanStopClearsThePriorProcess()
    {
        var current = Running(20);
        var watch = AgentUpdateWatchPolicy.Classify(new(), current, TimeSpan.Zero);
        watch = Take(watch, current with { ProcessId = 21 });
        Assert.Equal(1, watch.CrashRestarts);
        watch = Take(watch, current with { ProcessId = 21 });
        Assert.Equal(1, watch.CrashRestarts);
        watch = Take(watch, current with { ProcessId = 22 });
        Assert.Equal(AgentUpdateWatchOutcome.Open, Evaluate(watch));
        watch = Take(watch, current with { ProcessId = 23 });
        Assert.Equal(AgentUpdateWatchOutcome.RollbackPending, Evaluate(watch));
        Assert.Equal(AgentUpdateWatchOutcome.ForwardOnlyFailed, Evaluate(watch, hasLkg: false));
        Assert.Equal(AgentUpdateWatchOutcome.Superseded, Evaluate(watch, sameVersion: false));

        watch = Take(watch, current with { BootId = "next-boot", ProcessId = 40 });
        Assert.Equal(0, watch.CrashRestarts);
        watch = Take(watch, current with { BootId = "next-boot", State = AgentUpdateWatchServiceState.Stopped, ProcessId = null });
        watch = Take(watch, current with { BootId = "next-boot", ProcessId = 41 });
        Assert.Equal(0, watch.CrashRestarts);
    }

    [Fact]
    public void CountsOnlyRunningImageMismatchesOutsideInstallerAndPendingRename()
    {
        var running = Running(20);
        var mismatch = running with { ImageMismatch = true };
        var progress = Take(new(), mismatch with { InstallerMutexHeld = true });
        progress = Take(progress, mismatch with { State = AgentUpdateWatchServiceState.Stopped, ProcessId = null });
        Assert.Equal(0, progress.ImageMismatchStreak);
        progress = Take(progress, mismatch);
        Assert.Equal(AgentUpdateWatchOutcome.Open, Evaluate(progress));
        progress = Take(progress, mismatch with { CanonicalImagePendingRename = true });
        Assert.Equal(0, progress.ImageMismatchStreak);
        progress = Take(Take(progress, mismatch), mismatch);
        Assert.Equal(AgentUpdateWatchOutcome.RollbackPending, Evaluate(progress));
    }

    [Fact]
    public void PassRequiresObservedTimeAndACanonicalStableProcess()
    {
        var running = Running(20);
        var progress = Take(new(), running);
        progress = AgentUpdateWatchPolicy.Classify(progress, running, TimeSpan.FromSeconds(59));
        Assert.Equal(AgentUpdateWatchOutcome.Open, Evaluate(progress, observed: 30));
        progress = AgentUpdateWatchPolicy.Classify(progress, running, TimeSpan.FromSeconds(1));
        Assert.Equal(AgentUpdateWatchOutcome.Open, Evaluate(progress, observed: 29));
        Assert.Equal(AgentUpdateWatchOutcome.Passed, Evaluate(progress, observed: 30));
        Assert.Equal(AgentUpdateWatchOutcome.Inconclusive, Evaluate(Take(progress, running with { ProcessId = 21 }), observed: 240));
        Assert.Equal(AgentUpdateWatchOutcome.Inconclusive, AgentUpdateWatchPolicy.Evaluate(progress, true, true, true,
            TimeSpan.Zero, TimeSpan.FromHours(24)));
        Assert.Equal(12L, AgentUpdateWatchPolicy.PostCommitPin(12, 11));
        Assert.Equal(13L, AgentUpdateWatchPolicy.PostCommitPin(12, 13));
    }

    [Theory]
    [InlineData(true, false, false, 0, "WaitThenStart")]
    [InlineData(true, true, false, 1, "None")]
    [InlineData(false, false, true, 1, "None")]
    [InlineData(false, false, false, 1, "Start")]
    [InlineData(false, false, false, 0, "None")]
    public void RestartDependsOnLiveOwnershipAndScmOrObservedExit(bool scm, bool liveOwner, bool mutex,
        int exitCode, string expected)
    {
        var stopped = Running(20) with { ProcessId = null, State = AgentUpdateWatchServiceState.Stopped, Win32Exit = exitCode };
        Assert.Equal(Enum.Parse<AgentUpdateWatchRestart>(expected), AgentUpdateWatchPolicy.RestartDecision(stopped, scm, liveOwner, mutex));
        Assert.Equal(AgentUpdateWatchRestart.None, AgentUpdateWatchPolicy.RestartDecision(Running(20), scm, liveOwner, mutex));
    }

    private static AgentUpdateWatchSample Running(int pid)
        => new("boot", pid, Started, AgentUpdateWatchServiceState.Running, 0, 0, false, false, false);

    private static AgentUpdateWatchProgress Take(AgentUpdateWatchProgress progress, AgentUpdateWatchSample sample)
        => AgentUpdateWatchPolicy.Classify(progress, sample, SampleInterval);

    private static AgentUpdateWatchOutcome Evaluate(AgentUpdateWatchProgress progress, bool hasLkg = true,
        bool sameVersion = true, int observed = 0)
        => AgentUpdateWatchPolicy.Evaluate(progress, sameVersion, true, hasLkg, TimeSpan.FromMinutes(observed), TimeSpan.Zero);
}
