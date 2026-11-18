using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class LkgWatchSamplingTests
{
    private const string Boot = "11111111111111111111111111111111";
    private const string NextBoot = "22222222222222222222222222222222";
    private const string Version = "0.2.1020";
    private static readonly string Digest = new('a', 64);
    private static readonly string WrongDigest = new('b', 64);
    private static readonly DateTimeOffset Start = new(2026, 11, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly LkgWatchOpenInput Attempt = new("0123456789abcdef0123456789abcdef", Version, 100,
        Guid.Parse("d19d1cb9-1250-4eb0-aa1a-b1d01e28ee90"), "0.2.1019", "0.2.1019");

    [Fact]
    public void OpenRecordsOneFailedCommitSampleAndRequiresAnotherCountedMismatch()
    {
        var initial = At(0) with { ServiceImagePathCanonical = false, ProcessImagePathCanonical = false };
        var sampling = LkgWatchSampling.Open(Attempt, initial, () => WrongDigest);

        Assert.Equal(AgentUpdateWatchOutcomes.Open, sampling.Record.Outcome);
        Assert.Equal(Attempt.AttemptId, sampling.Record.AttemptId);
        Assert.Equal(Attempt.Version, sampling.Record.WatchedVersion);
        Assert.Equal(Attempt.Sequence, sampling.Record.WatchedSequence);
        Assert.Equal(Attempt.ProductCode, sampling.Record.WatchedProductCode);
        Assert.Equal(Attempt.ReplacedVersion, sampling.Record.ReplacedVersion);
        Assert.Equal(Attempt.ValidatedLkgVersion, sampling.Record.LkgVersion);
        Assert.Equal(1, sampling.Record.ImageMismatchStreak);
        Assert.False(sampling.Sample(initial with { TickCount64 = 1000 }, () => WrongDigest, 30).ShouldPersist);

        var tick = sampling.Sample(initial with { TickCount64 = 2000 }, () => WrongDigest, 30);
        Assert.True(tick.ShouldPersist);
        Assert.Equal(2, tick.Record.ImageMismatchStreak);
        Assert.Equal(AgentUpdateWatchOutcome.RollbackPending, tick.Decision);
    }

    [Fact]
    public void HashesOnOpenMetadataChangeAndHostResumeAndPersistsOnChangeOrAfterOneMinute()
    {
        var reads = 0;
        string ReadHash()
        {
            reads++;
            return Digest;
        }

        var initial = At(0);
        var sampling = LkgWatchSampling.Open(Attempt, initial, ReadHash);
        for (var second = 2; second < 60; second += 2)
            Assert.False(sampling.Sample(At(second), ReadHash, 30).ShouldPersist);
        Assert.True(sampling.Sample(At(60), ReadHash, 30).ShouldPersist);
        Assert.Equal(1, reads);

        var resized = At(62) with { Image = initial.Image! with { Size = 200 } };
        Assert.True(sampling.Sample(resized, ReadHash, 30).ShouldPersist);
        var modified = resized with { TickCount64 = 64000, Image = resized.Image! with { LastWriteUtc = Start.AddSeconds(62) } };
        Assert.True(sampling.Sample(modified, ReadHash, 30).ShouldPersist);
        Assert.Equal(3, reads);

        // A change in the expected digest can reuse the observed file's cached digest.
        var changedDigest = modified with { TickCount64 = 66000, CommittedImageSha256 = WrongDigest };
        Assert.Equal(1, sampling.Sample(changedDigest, ReadHash, 30).Record.ImageMismatchStreak);
        Assert.Equal(3, reads);

        var resumed = LkgWatchSampling.Resume(sampling.Record);
        Assert.True(resumed.Sample(modified with { TickCount64 = 68000 }, ReadHash, 30).ShouldPersist);
        Assert.Equal(4, reads);
    }

    [Fact]
    public void InstallerAndStoppedSamplesAreUncountedAndPendingRenameClearsTheStreak()
    {
        var initial = At(0) with { ProcessImagePathCanonical = false };
        var sampling = LkgWatchSampling.Open(Attempt, initial, () => Digest);
        var duringInstall = At(2);
        duringInstall = duringInstall with
        {
            Service = duringInstall.Service with { InstallerMutexHeld = true },
            ProcessImagePathCanonical = false,
        };
        Assert.Equal(1, sampling.Sample(duringInstall, () => Digest, 30).Record.ImageMismatchStreak);
        Assert.Equal(1, sampling.Sample(Stopped(4, 0) with { ServiceImagePathCanonical = false }, () => Digest, 30)
            .Record.ImageMismatchStreak);
        var pendingRename = At(6);
        pendingRename = pendingRename with
        {
            Service = pendingRename.Service with { CanonicalImagePendingRename = true },
            ProcessImagePathCanonical = false,
        };
        Assert.Equal(0, sampling.Sample(pendingRename, () => Digest, 30).Record.ImageMismatchStreak);

        var unavailable = At(8) with { ProcessImagePathCanonical = null };
        Assert.Equal(0, sampling.Sample(unavailable, () => Digest, 30).Record.ImageMismatchStreak);

        var mismatch = At(10) with { ServiceImagePathCanonical = false, EligibleLkg = false };
        Assert.Equal(AgentUpdateWatchOutcome.Open, sampling.Sample(mismatch, () => Digest, 30).Decision);
        Assert.Equal(AgentUpdateWatchOutcome.ForwardOnlyFailed,
            sampling.Sample(mismatch with { TickCount64 = 12000 }, () => Digest, 30).Decision);
    }

    [Theory]
    [InlineData("version")]
    [InlineData("journal")]
    [InlineData("generation")]
    public void ChangedIdentitySupersedesTheWatchBeforeAnotherSampleIsCounted(string changed)
    {
        var sampling = LkgWatchSampling.Open(Attempt, At(0), () => Digest);
        var next = At(2, pid: 21) with
        {
            InstalledVersion = changed == "version" ? "0.2.1021" : Version,
            JournalStillWatchesAttempt = changed != "journal",
            LifecycleGenerationMatches = changed != "generation",
        };
        var tick = sampling.Sample(next, () => throw new InvalidOperationException("Superseded watch read the image."), 30);
        Assert.True(tick.ShouldPersist);
        Assert.Equal(AgentUpdateWatchOutcome.Superseded, tick.Decision);
        Assert.Equal(0, tick.Record.CrashRestarts);
    }

    private static LkgWatchObservation At(int second, int pid = 20, string boot = Boot)
        => new(new(boot, pid, Start, AgentUpdateWatchServiceState.Running, 0, 0, false, false, false),
            second * 1000L, Start.AddSeconds(second), Version, true, true, true, true, true, Digest,
            new(100, Start));

    private static LkgWatchObservation Stopped(int second, int exit)
    {
        var observation = At(second);
        return observation with
        {
            Service = observation.Service with
            {
                ProcessId = null,
                ProcessStartedUtc = null,
                State = AgentUpdateWatchServiceState.Stopped,
                Win32Exit = exit,
            },
            ProcessImagePathCanonical = null,
        };
    }
}
