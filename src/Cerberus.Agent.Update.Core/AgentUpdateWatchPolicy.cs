namespace Cerberus.Agent.Core;

internal enum AgentUpdateWatchOutcome { Open, Passed, RollbackPending, ForwardOnlyFailed, Superseded, Inconclusive }
internal enum AgentUpdateWatchServiceState { Stopped, Starting, Running, Stopping, Other }
internal enum AgentUpdateWatchRestart { None, Start, WaitThenStart }

internal sealed record AgentUpdateWatchSample(string BootId, int? ProcessId, DateTimeOffset? ProcessStartedUtc,
    AgentUpdateWatchServiceState State, int Win32Exit, int ServiceExit, bool ImageMismatch,
    bool InstallerMutexHeld, bool CanonicalImagePendingRename)
{
    public bool CleanStop => State == AgentUpdateWatchServiceState.Stopped && Win32Exit == 0 && ServiceExit == 0;
}

internal sealed record AgentUpdateWatchProgress(AgentUpdateWatchSample? LastSample = null,
    AgentUpdateWatchSample? LastRunningSample = null, int CrashRestarts = 0, int ImageMismatchStreak = 0,
    TimeSpan CanonicalRunningTime = default);

internal static class AgentUpdateWatchPolicy
{
    public static readonly TimeSpan RequiredObservation = TimeSpan.FromMinutes(30);
    public static readonly TimeSpan RequiredStableRunning = TimeSpan.FromMinutes(1);

    /// <summary>Monotonic elapsed time comes from the host, with a zero delta across boots and on an unobserved resume.</summary>
    public static AgentUpdateWatchProgress Classify(AgentUpdateWatchProgress previous, AgentUpdateWatchSample sample,
        TimeSpan elapsed)
    {
        var sameBoot = previous.LastSample?.BootId == sample.BootId;
        var running = sample.State == AgentUpdateWatchServiceState.Running && sample.ProcessId is > 0;
        var lastRunning = sameBoot ? previous.LastRunningSample : null;
        var changedProcess = lastRunning is not null && (lastRunning.ProcessId != sample.ProcessId ||
            (lastRunning.ProcessStartedUtc is not null && sample.ProcessStartedUtc is not null && !SameProcess(lastRunning, sample)));
        var crash = running && changedProcess && previous.LastSample?.CleanStop != true;
        var crashes = sameBoot ? previous.CrashRestarts : 0;
        var mismatchStreak = previous.ImageMismatchStreak;
        var canonical = running && sample.ProcessStartedUtc is not null && !sample.ImageMismatch;
        if (running && !sample.InstallerMutexHeld && !sample.CanonicalImagePendingRename)
            mismatchStreak = sample.ImageMismatch ? mismatchStreak + 1 : 0;
        else if (sample.CanonicalImagePendingRename)
            mismatchStreak = 0;

        var uninterrupted = canonical && sameBoot && !changedProcess && !sample.InstallerMutexHeld &&
            !sample.CanonicalImagePendingRename && previous.LastSample is
                { State: AgentUpdateWatchServiceState.Running, ImageMismatch: false, InstallerMutexHeld: false,
                    CanonicalImagePendingRename: false } prior && SameProcess(prior, sample);
        return new(sample, running ? sample : sample.CleanStop ? null : lastRunning, crashes + (crash ? 1 : 0), mismatchStreak,
            uninterrupted && elapsed >= TimeSpan.Zero ? previous.CanonicalRunningTime + elapsed : TimeSpan.Zero);
    }

    public static AgentUpdateWatchOutcome Evaluate(AgentUpdateWatchProgress progress, bool versionAndGenerationMatch,
        bool journalStillWatchesAttempt, bool eligibleLkg, TimeSpan observed, TimeSpan wallTime)
    {
        if (!versionAndGenerationMatch || !journalStillWatchesAttempt) return AgentUpdateWatchOutcome.Superseded;
        if (progress.CrashRestarts >= 3 || progress.ImageMismatchStreak >= 2)
            return eligibleLkg ? AgentUpdateWatchOutcome.RollbackPending : AgentUpdateWatchOutcome.ForwardOnlyFailed;
        if (observed >= RequiredObservation && progress.CanonicalRunningTime >= RequiredStableRunning)
            return AgentUpdateWatchOutcome.Passed;
        if (observed >= TimeSpan.FromHours(4) || wallTime >= TimeSpan.FromHours(24))
            return AgentUpdateWatchOutcome.Inconclusive;
        return AgentUpdateWatchOutcome.Open;
    }

    public static AgentUpdateWatchRestart RestartDecision(AgentUpdateWatchSample service, bool invokedByScm,
        bool journalProcessAlive, bool installerMutexHeld)
    {
        if (journalProcessAlive || installerMutexHeld) return AgentUpdateWatchRestart.None;
        if (invokedByScm) return service.State == AgentUpdateWatchServiceState.Running
            ? AgentUpdateWatchRestart.None : AgentUpdateWatchRestart.WaitThenStart;
        return service.State == AgentUpdateWatchServiceState.Stopped && !service.CleanStop
            ? AgentUpdateWatchRestart.Start : AgentUpdateWatchRestart.None;
    }

    public static long PostCommitPin(long previous, long watchedSequence) => Math.Max(previous, watchedSequence);

    private static bool SameProcess(AgentUpdateWatchSample left, AgentUpdateWatchSample right)
        => left.ProcessId == right.ProcessId && left.ProcessStartedUtc == right.ProcessStartedUtc;
}
