using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class LkgWatchSamplingTests
{
    [Fact]
    public void ResumeRetainsAbnormalStopIdentityAndCountsEachReplacementOnlyOnce()
    {
        var sampling = LkgWatchSampling.Open(Attempt, At(0), () => Digest);
        var stopped = sampling.Sample(Stopped(2, 1067), () => Digest, 30).Record;
        Assert.Equal(20, stopped.LastSample!.Pid);

        var resumed = LkgWatchSampling.Resume(stopped);
        var first = resumed.Sample(At(120, pid: 21), () => Digest, 30);
        Assert.Equal(1, first.Record.CrashRestarts);
        Assert.Equal(2000, Assert.Single(first.Record.Segments).ObservedMs);
        Assert.Equal(1, resumed.Sample(At(122, pid: 21), () => Digest, 30).Record.CrashRestarts);

        resumed = LkgWatchSampling.Resume(resumed.Record);
        Assert.Equal(1, resumed.Sample(At(124, pid: 21), () => Digest, 30).Record.CrashRestarts);
        Assert.Equal(AgentUpdateWatchOutcome.Open, resumed.Sample(At(126, pid: 22), () => Digest, 30).Decision);
        Assert.Equal(AgentUpdateWatchOutcome.RollbackPending, resumed.Sample(At(128, pid: 23), () => Digest, 30).Decision);
    }

    [Fact]
    public void BootChangeResetsCrashCountAndCleanStopSuppressesTheNextRestart()
    {
        var sampling = LkgWatchSampling.Open(Attempt, At(0), () => Digest);
        Assert.Equal(1, sampling.Sample(At(2, pid: 21), () => Digest, 30).Record.CrashRestarts);
        var next = At(1, pid: 40, boot: NextBoot) with { UtcNow = Start.AddMinutes(3) };
        var tick = sampling.Sample(next, () => Digest, 30);
        Assert.Equal(0, tick.Record.CrashRestarts);
        Assert.Collection(tick.Record.Segments,
            segment => Assert.Equal(new(Boot, 2000), segment),
            segment => Assert.Equal(new(NextBoot, 0), segment));

        var stopped = Stopped(3, 0);
        stopped = stopped with { Service = stopped.Service with { BootId = NextBoot } };
        var resumed = LkgWatchSampling.Resume(sampling.Sample(stopped, () => Digest, 30).Record);
        Assert.Equal(0, resumed.Sample(At(7, pid: 41, boot: NextBoot), () => Digest, 30).Record.CrashRestarts);
    }

    [Fact]
    public void SamePidWithDifferentStartCountsAfterAnUnreadableProcessTime()
    {
        var sampling = LkgWatchSampling.Open(Attempt, At(0), () => Digest);
        var missingTime = At(2);
        missingTime = missingTime with { Service = missingTime.Service with { ProcessStartedUtc = null } };
        Assert.Equal(0, sampling.Sample(missingTime, () => Digest, 30).Record.CrashRestarts);
        var replacement = At(4);
        replacement = replacement with { Service = replacement.Service with { ProcessStartedUtc = Start.AddSeconds(1) } };
        Assert.Equal(1, sampling.Sample(replacement, () => Digest, 30).Record.CrashRestarts);
    }

    [Fact]
    public void ResumeUsesTheSameBootSegmentForEitherHexCase()
    {
        const string boot = "abcdefabcdefabcdefabcdefabcdefab";
        var initial = LkgWatchSampling.Open(Attempt, At(0, boot: boot), () => Digest).Record;
        var upper = boot.ToUpperInvariant();
        var saved = initial with { Segments = [new(upper, 1000)], LastSample = initial.LastSample! with { BootId = upper } };
        var resumed = LkgWatchSampling.Resume(saved);
        Assert.Equal(1, resumed.Sample(At(120, pid: 21, boot: boot), () => Digest, 30).Record.CrashRestarts);
        var next = resumed.Sample(At(122, pid: 21, boot: boot), () => Digest, 30);
        Assert.Equal(3000, Assert.Single(next.Record.Segments).ObservedMs);
        next.Record.Validate();
    }
}
