using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class LkgWatchSamplingTests
{
    [Theory]
    [InlineData(5)]
    [InlineData(30)]
    public void PassUsesObservedMinutesAndAFullMinuteFromTheSameCanonicalProcess(int watchMinutes)
    {
        var sampling = LkgWatchSampling.Open(Attempt, At(0), () => Digest);
        var threshold = watchMinutes * 60;
        for (var second = 2; second < threshold; second += 2)
        {
            var sample = At(second) with { UtcNow = Start.AddHours(12) };
            Assert.Equal(AgentUpdateWatchOutcome.Open, sampling.Sample(sample, () => Digest, watchMinutes).Decision);
        }

        var changed = sampling.Sample(At(threshold, pid: 21), () => Digest, watchMinutes);
        Assert.Equal(AgentUpdateWatchOutcome.Open, changed.Decision);
        for (var second = threshold + 2; second < threshold + 60; second += 2)
            Assert.Equal(AgentUpdateWatchOutcome.Open, sampling.Sample(At(second, pid: 21), () => Digest, watchMinutes).Decision);
        Assert.Equal(AgentUpdateWatchOutcome.Passed,
            sampling.Sample(At(threshold + 60, pid: 21), () => Digest, watchMinutes).Decision);
    }

    [Fact]
    public void ResumeAndMissedSamplesCannotCreditStableTimeOrUnobservedMilliseconds()
    {
        var initial = LkgWatchSampling.Open(Attempt, At(0), () => Digest).Record;
        var sampling = LkgWatchSampling.Resume(initial with { Segments = [new(Boot, 1_800_000)] });
        for (var second = 120; second < 180; second += 2)
            Assert.Equal(AgentUpdateWatchOutcome.Open, sampling.Sample(At(second), () => Digest, 30).Decision);
        var afterGap = sampling.Sample(At(240), () => Digest, 30);
        Assert.Equal(1_858_000, Assert.Single(afterGap.Record.Segments).ObservedMs);
        Assert.Equal(AgentUpdateWatchOutcome.Open, afterGap.Decision);
        Assert.Equal(AgentUpdateWatchOutcome.Open, sampling.Sample(At(242), () => Digest, 30).Decision);
        for (var second = 244; second < 300; second += 2)
            sampling.Sample(At(second), () => Digest, 30);
        Assert.Equal(AgentUpdateWatchOutcome.Passed, sampling.Sample(At(300), () => Digest, 30).Decision);
    }

    [Fact]
    public void UnknownImageOrIdentityCannotAccrueCanonicalRunningTime()
    {
        var initial = LkgWatchSampling.Open(Attempt, At(0), () => Digest).Record;
        var sampling = LkgWatchSampling.Resume(initial with { Segments = [new(Boot, 1_800_000)] });
        for (var second = 2; second <= 60; second += 2)
        {
            var reading = At(second) with { ProcessImagePathCanonical = null };
            Assert.Equal(AgentUpdateWatchOutcome.Open, sampling.Sample(reading, () => Digest, 30).Decision);
        }
        for (var second = 62; second <= 122; second += 2)
        {
            var reading = At(second) with { JournalStillWatchesAttempt = null };
            Assert.Equal(AgentUpdateWatchOutcome.Open, sampling.Sample(reading, () => Digest, 30).Decision);
        }
        Assert.Equal(AgentUpdateWatchOutcome.Open, sampling.Sample(At(124), () => Digest, 30).Decision);
    }

    [Fact]
    public void FourHoursObservedOrTwentyFourHoursWallClosesAsInconclusive()
    {
        var initial = LkgWatchSampling.Open(Attempt, At(0), () => Digest).Record;
        var observed = LkgWatchSampling.Resume(initial with { Segments = [new(Boot, 14_398_000)] });
        Assert.Equal(AgentUpdateWatchOutcome.Open, observed.Sample(Stopped(2, 0), () => Digest, 30).Decision);
        Assert.Equal(AgentUpdateWatchOutcome.Inconclusive, observed.Sample(Stopped(4, 0), () => Digest, 30).Decision);

        var wall = LkgWatchSampling.Resume(initial);
        var noJournal = Stopped(2, 0) with { UtcNow = Start.AddHours(24), JournalStillWatchesAttempt = null };
        Assert.Equal(AgentUpdateWatchOutcome.Inconclusive, wall.Sample(noJournal, () => Digest, 30).Decision);
    }
}
