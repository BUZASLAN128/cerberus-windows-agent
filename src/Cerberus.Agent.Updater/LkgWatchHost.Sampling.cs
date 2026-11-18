using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal sealed record LkgWatchOpenInput(string AttemptId, string Version, long Sequence, Guid ProductCode,
    string? ReplacedVersion, string? ValidatedLkgVersion);

internal sealed record LkgWatchImageStamp(long Size, DateTimeOffset LastWriteUtc);

/// <summary>Read-only observations for this attempt. Null evidence means the source could not be verified.</summary>
internal sealed record LkgWatchObservation(AgentUpdateWatchSample Service, long TickCount64, DateTimeOffset UtcNow,
    string? InstalledVersion, bool? JournalStillWatchesAttempt, bool? LifecycleGenerationMatches, bool EligibleLkg,
    bool? ServiceImagePathCanonical, bool? ProcessImagePathCanonical, string? CommittedImageSha256,
    LkgWatchImageStamp? Image);

internal sealed record LkgWatchTick(AgentUpdateWatchRecord Record, bool ShouldPersist, AgentUpdateWatchOutcome Decision);

/// <summary>Runs under the watch host lock. The host owns persistence and terminal compare-and-set routing.</summary>
internal sealed class LkgWatchSampling
{
    internal static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan PersistInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan ObservationLimit = TimeSpan.FromHours(4);
    private static readonly TimeSpan WallLimit = TimeSpan.FromHours(24);

    private AgentUpdateWatchProgress _progress;
    private LkgWatchObservation? _last;
    private LkgWatchImageStamp? _hashedImage;
    private string? _imageSha256;
    private bool _lastCanonical;
    private long _firstTick;
    private long _lastPersistTick;

    internal AgentUpdateWatchRecord Record { get; private set; }

    private LkgWatchSampling(AgentUpdateWatchRecord record)
    {
        record.Validate();
        if (record.Outcome != AgentUpdateWatchOutcomes.Open)
            throw new InvalidOperationException("Only an open update watch can be sampled.");

        Record = record;
        var last = record.LastSample;
        var sample = last is null ? null : new AgentUpdateWatchSample(last.BootId.ToLowerInvariant(), last.Pid,
            last.ProcessStartUtc, last.State, last.Win32Exit, last.SvcExit, false, false, false);
        var lastRunning = sample is { ProcessId: > 0, CleanStop: false }
            ? sample with { State = AgentUpdateWatchServiceState.Running }
            : null;
        _progress = new(sample, lastRunning, record.CrashRestarts, record.ImageMismatchStreak);
    }

    internal static LkgWatchSampling Open(LkgWatchOpenInput input, LkgWatchObservation initial,
        Func<string?> readImageSha256)
    {
        initial = NormalizeObservation(initial);
        var record = new AgentUpdateWatchRecord(AgentUpdateWatchRecord.CurrentSchema, input.AttemptId, input.Version,
            input.Sequence, input.ProductCode, input.ReplacedVersion, input.ValidatedLkgVersion,
            initial.UtcNow.ToUniversalTime(), [], null, 0, 0, null, null, AgentUpdateWatchOutcomes.Open, []);
        var sampling = new LkgWatchSampling(record);
        var versionMatches = sampling.InstalledVersionMatches(initial);
        var hashMatches = sampling.ImageHashMatches(initial, readImageSha256);
        var commitMatches = versionMatches & initial.ServiceImagePathCanonical & hashMatches;
        sampling.Observe(initial, commitMatches & initial.ProcessImagePathCanonical,
            initial.JournalStillWatchesAttempt == true && initial.LifecycleGenerationMatches == true, 0);
        sampling.Record.Validate();
        sampling._lastPersistTick = initial.TickCount64;
        return sampling;
    }

    internal static LkgWatchSampling Resume(AgentUpdateWatchRecord record) => new(record);

    internal LkgWatchTick Sample(LkgWatchObservation observation, Func<string?> readImageSha256, int watchMinutes)
    {
        observation = NormalizeObservation(observation);
        ArgumentOutOfRangeException.ThrowIfLessThan(watchMinutes, 5);
        var sameBoot = _last?.Service.BootId == observation.Service.BootId;
        var delta = sameBoot ? observation.TickCount64 - _last!.TickCount64 : 0;
        if (sameBoot && delta < SampleInterval.TotalMilliseconds)
            return new(Record, false, AgentUpdateWatchOutcome.Open);

        var before = Record;
        var previousService = _progress.LastSample;
        var versionMatches = InstalledVersionMatches(observation);
        var identityMatches = versionMatches & observation.LifecycleGenerationMatches & observation.JournalStillWatchesAttempt;
        if (identityMatches == false)
            return new(Record, true, AgentUpdateWatchOutcome.Superseded);

        var service = observation.Service;
        bool? imageMatches = null;
        if (service.State == AgentUpdateWatchServiceState.Running &&
            service.ProcessId is > 0 && !service.InstallerMutexHeld && !service.CanonicalImagePendingRename)
            imageMatches = observation.ServiceImagePathCanonical & observation.ProcessImagePathCanonical &
                ImageHashMatches(observation, readImageSha256);

        // Missed samples and sleep are gaps in observation. Allow one sampling interval of scheduler delay.
        var elapsedMs = delta <= 2 * SampleInterval.TotalMilliseconds ? delta : 0;
        Observe(observation, imageMatches, identityMatches == true, elapsedMs);
        var decision = Decide(observation, identityMatches, TimeSpan.FromMinutes(watchMinutes));
        var persist = !sameBoot || decision != AgentUpdateWatchOutcome.Open ||
            observation.TickCount64 - _lastPersistTick >= PersistInterval.TotalMilliseconds ||
            before.LastSample != Record.LastSample || previousService != _progress.LastSample ||
            before.CrashRestarts != Record.CrashRestarts || before.ImageMismatchStreak != Record.ImageMismatchStreak ||
            before.ExeSize != Record.ExeSize || before.ExeMtime != Record.ExeMtime;
        if (persist)
            _lastPersistTick = observation.TickCount64;
        return new(Record, persist, decision);
    }

    private void Observe(LkgWatchObservation observation, bool? imageMatches, bool identityMatches, long elapsedMs)
    {
        var service = observation.Service with { ImageMismatch = imageMatches == false };
        var previous = _progress;
        var baseline = elapsedMs == 0 ? previous with { CanonicalRunningTime = TimeSpan.Zero } : previous;
        _progress = AgentUpdateWatchPolicy.Classify(baseline, service,
            TimeSpan.FromMilliseconds(_lastCanonical && imageMatches == true ? elapsedMs : 0));

        // Preserve the last counted streak when a read is unavailable. Stable time needs positive image evidence.
        if (imageMatches is null && !service.CanonicalImagePendingRename)
            _progress = _progress with { ImageMismatchStreak = previous.ImageMismatchStreak };
        _lastCanonical = identityMatches && imageMatches == true && !service.InstallerMutexHeld &&
            !service.CanonicalImagePendingRename;
        if (!_lastCanonical)
            _progress = _progress with { CanonicalRunningTime = TimeSpan.Zero };

        if (_progress.LastRunningSample is { ProcessStartedUtc: null } running &&
            previous.LastRunningSample is { ProcessStartedUtc: not null } confirmed &&
            running.BootId == confirmed.BootId && running.ProcessId == confirmed.ProcessId)
            _progress = _progress with { LastRunningSample = confirmed };

        if (_last?.Service.BootId != service.BootId)
            _firstTick = observation.TickCount64;
        _last = observation;

        // SCM may report no PID during an abnormal stop. Keep the prior running identity for resume deduplication.
        var process = _progress.LastRunningSample;
        Record = Record with
        {
            Segments = AddObservation(Record.Segments, service.BootId, elapsedMs),
            LastSample = new(service.BootId, process?.ProcessId, process?.ProcessStartedUtc,
                service.State, service.Win32Exit, service.ServiceExit),
            CrashRestarts = _progress.CrashRestarts,
            ImageMismatchStreak = _progress.ImageMismatchStreak,
            ExeSize = observation.Image?.Size,
            ExeMtime = observation.Image?.LastWriteUtc,
        };
    }

    private AgentUpdateWatchOutcome Decide(LkgWatchObservation observation, bool? identityMatches, TimeSpan required)
    {
        var observed = TimeSpan.Zero;
        foreach (var segment in Record.Segments)
            observed += TimeSpan.FromMilliseconds(Math.Min(segment.ObservedMs, (ObservationLimit - observed).TotalMilliseconds));
        var utcAge = observation.UtcNow - Record.StartedUtc;
        var sessionAge = TimeSpan.FromMilliseconds(Math.Min((double)(observation.TickCount64 - _firstTick),
            WallLimit.TotalMilliseconds));
        var wallTime = utcAge > sessionAge ? utcAge : sessionAge;
        if (identityMatches is null)
            return observed >= ObservationLimit || wallTime >= WallLimit
                ? AgentUpdateWatchOutcome.Inconclusive : AgentUpdateWatchOutcome.Open;

        var decision = AgentUpdateWatchPolicy.Evaluate(_progress, identityMatches.Value, true,
            observation.EligibleLkg, observed, wallTime);
        if (required == AgentUpdateWatchPolicy.RequiredObservation ||
            decision is AgentUpdateWatchOutcome.Superseded or AgentUpdateWatchOutcome.RollbackPending or
                AgentUpdateWatchOutcome.ForwardOnlyFailed)
            return decision;

        if (observed >= required && _progress.CanonicalRunningTime >= AgentUpdateWatchPolicy.RequiredStableRunning)
            return AgentUpdateWatchOutcome.Passed;
        return decision == AgentUpdateWatchOutcome.Passed
            ? AgentUpdateWatchPolicy.Evaluate(_progress with { CanonicalRunningTime = TimeSpan.Zero }, true, true,
                observation.EligibleLkg, observed, wallTime)
            : decision;
    }

    private bool? InstalledVersionMatches(LkgWatchObservation observation) => observation.InstalledVersion is { } version
        ? string.Equals(version, Record.WatchedVersion, StringComparison.Ordinal)
        : null;

    // The reader returns null if it cannot hash the canonical file at the observed stamp.
    private bool? ImageHashMatches(LkgWatchObservation observation, Func<string?> readImageSha256)
    {
        if (observation.Image is not { } image || !AgentUpdateManifestValidator.IsSha256(observation.CommittedImageSha256))
            return null;
        if (_hashedImage != image)
        {
            var digest = readImageSha256();
            _imageSha256 = AgentUpdateManifestValidator.IsSha256(digest) ? digest : null;
            _hashedImage = _imageSha256 is not null ? image : null;
        }
        return _imageSha256 is null ? null : string.Equals(_imageSha256, observation.CommittedImageSha256,
            StringComparison.OrdinalIgnoreCase);
    }

    private static LkgWatchObservation NormalizeObservation(LkgWatchObservation observation)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(observation.TickCount64);
        if (!Guid.TryParseExact(observation.Service.BootId, "N", out var boot) || boot == Guid.Empty)
            throw new ArgumentException("A valid boot identity is required for an update watch.", nameof(observation));
        var bootId = observation.Service.BootId.ToLowerInvariant();
        return bootId == observation.Service.BootId
            ? observation
            : observation with { Service = observation.Service with { BootId = bootId } };
    }

    private static IReadOnlyList<AgentUpdateWatchSegment> AddObservation(IReadOnlyList<AgentUpdateWatchSegment> segments,
        string bootId, long elapsedMs)
    {
        if (segments is [.., var current] && string.Equals(current.BootId, bootId, StringComparison.OrdinalIgnoreCase))
        {
            if (elapsedMs == 0)
                return segments;
            var updated = Math.Min((long)ObservationLimit.TotalMilliseconds, current.ObservedMs) + elapsedMs;
            return [.. segments.Take(segments.Count - 1), current with { ObservedMs = updated }];
        }
        return [.. segments, new AgentUpdateWatchSegment(bootId, 0)];
    }
}
