namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

/// <summary>
/// Builds the <c>security.failed_logons</c> object. Each collection reports the window since the last committed
/// one (<c>window_start_utc</c> = last committed window end). The very first run has no history: it starts at the
/// current end of every log, reports zeros and is not a cursor reset. Successful logons are the exception: until a
/// committed window has carried them (<see cref="FailedLogonCursorState.SuccessfulLogonsSeeded"/>), each committing pass
/// also reports those of the last week before the window, so logons from before install or upgrade show up; the
/// receiver deduplicates the repeat. A reset (cleared log, regressed record id,
/// log wrapped past the saved id, 1102/104 clear event, invalid cursor file) sets <c>cursor_reset</c>; cleared or
/// invalid positions restart at the current end of the log, a wrapped log resumes at its oldest retained record.
/// <para>
/// Only the scheduled snapshot path (<c>commit: true</c>) produces a pending cursor, which
/// <see cref="CommitPending"/> persists after the snapshot upload succeeded; a failed upload leaves the committed
/// cursor untouched, so the next collection reads the same attempts again. Every other caller peeks
/// (<c>commit: false</c>): it reads forward from the committed cursor and never writes. A pending cursor is bound to
/// the report object it produced: <see cref="KeepPendingIfReported"/> drops it unless the snapshot being uploaded
/// carries that very object, so a timed-out, failed or skipped collection never commits an unreported window.
/// </para>
/// </summary>
internal static class FailedLogonSection
{
    // Gate only guards the pending fields and is never held across event-log or file I/O. CollectGuard keeps a single
    // collection reading at a time; a caller waits for it up to CollectWait (under the 5 s section budget) and then
    // gets an unavailable result. StoreLock serialises cursor-file Load and Save (never held across event-log reads).
    internal static readonly TimeSpan CollectWait = TimeSpan.FromSeconds(3);
    private static readonly object Gate = new();
    private static readonly SemaphoreSlim CollectGuard = new(1, 1);
    private static readonly object StoreLock = new();
    private static (FailedLogonCursorStore Store, FailedLogonCursorState State, object Report)? _pending;
    // Bumped when a committing collection starts and when KeepPendingIfReported runs: a collection that finishes
    // after either (timed out and abandoned) cannot stage a pending cursor.
    private static long _generation;
    // First-run baseline whose cursor file could not be written: kept so the next collection counts from it instead of
    // re-baselining at the then-current log ends. Guarded by Gate; dropped once a save succeeds.
    private static (FailedLogonCursorStore Store, FailedLogonCursorState State)? _baseline;

    /// <summary>The <c>failed_logons</c> object of <see cref="CollectAll"/>.</summary>
    public static object Collect(FailedLogonCursorStore store, DateTimeOffset now, bool commit, CancellationToken ct)
        => CollectAll(store, now, commit, ct).FailedLogons;

    /// <summary>
    /// One bounded pass over the channels. The Security scan also yields the successful interactive logons, the
    /// privileged group changes and the newest log clear; they share the failed-logon window, cursor and commit, so
    /// they are consume-once exactly like <c>failed_logons</c>.
    /// </summary>
    public static SecurityLogResult CollectAll(FailedLogonCursorStore store, DateTimeOffset now, bool commit, CancellationToken ct)
    {
        // A committing collection supersedes any earlier pending cursor even if it is cancelled or times out waiting.
        long generation = 0;
        if (commit)
        {
            lock (Gate)
            {
                _pending = null;
                generation = ++_generation;
            }
        }

        if (!CollectGuard.Wait(CollectWait, ct))
            return SecurityLogResult.Unavailable(now);
        try
        {
            return CollectCore(store, now, commit, generation, ct);
        }
        finally
        {
            CollectGuard.Release();
        }
    }

    /// <summary>Stages the pending cursor unless a newer committing collection or a snapshot build superseded <paramref name="generation"/>.</summary>
    internal static bool TryStage(long generation, FailedLogonCursorStore store, FailedLogonCursorState state, object report)
    {
        lock (Gate)
        {
            if (_generation != generation)
                return false;
            _pending = (store, state, report);
            return true;
        }
    }

    internal static long Generation
    {
        get
        {
            lock (Gate)
                return _generation;
        }
    }

    internal static bool HasPending
    {
        get
        {
            lock (Gate)
                return _pending is not null;
        }
    }

    private static FailedLogonCursorState LoadCursor(FailedLogonCursorStore store, out bool invalid)
    {
        lock (StoreLock)
            return store.Load(out invalid);
    }

    private static bool SaveCursor(FailedLogonCursorStore store, FailedLogonCursorState state)
    {
        lock (StoreLock)
            return store.Save(state);
    }

    private static SecurityLogResult CollectCore(FailedLogonCursorStore store, DateTimeOffset now, bool commit, long generation, CancellationToken ct)
    {
        var state = LoadCursor(store, out var invalid);
        state = ApplyRetainedBaseline(store, state, invalid);
        var firstRun = !invalid && state.LastWindowEndUtc is null;
        var start = state.LastWindowEndUtc is { } prev && prev <= now ? prev : now;
        var events = new List<FailedLogonEvent>();
        var securityEvents = new List<FailedLogonEvent>();
        var lookback = new List<FailedLogonEvent>();
        var lookbackRead = false;
        var securityReadable = false;
        var securityCapped = false;
        var securityResetOrGap = false;
        var securityFresh = false;
        var reset = false;
        var capped = false;
        var failed = 0;
        var readable = 0;

        foreach (var channel in FailedLogonEventReader.Channels)
        {
            ct.ThrowIfCancellationRequested();
            var bounds = FailedLogonEventReader.Bounds(channel, out var present);
            if (!present)
            {
                // Optional channels are absent when their service is not installed.
                if (channel == FailedLogonEventReader.Security)
                    failed++;
                continue;
            }
            if (bounds is not { } b)
            {
                failed++;
                continue;
            }

            long? saved = state.Channels.TryGetValue(channel, out var s) ? s : null;
            var decision = FailedLogonCursorLogic.Decide(saved, b.Oldest, b.Newest, invalid);
            reset |= FailedLogonCursorLogic.IsReset(decision);
            if (channel == FailedLogonEventReader.Security)
            {
                securityResetOrGap = FailedLogonCursorLogic.IsReset(decision);
                securityFresh = decision != ChannelStart.Resume;
            }
            var after = FailedLogonCursorLogic.StartAfter(decision, saved, b.Oldest, b.Newest);
            // A wrapped log has nothing at or below the window start; the next window looks back instead.
            if (channel == FailedLogonEventReader.Security && commit && !state.SuccessfulLogonsSeeded && decision != ChannelStart.Gap)
                lookbackRead = LookBack(after, lookback, ct);
            if (decision is ChannelStart.FirstRun or ChannelStart.Reset)
            {
                state.Channels[channel] = after;
                readable++;
                securityReadable |= channel == FailedLogonEventReader.Security;
                continue;
            }

            var read = FailedLogonEventReader.Read(channel, after, ct);
            if (read.Failed)
            {
                failed++;
                continue;
            }
            readable++;
            securityReadable |= channel == FailedLogonEventReader.Security;
            capped |= read.Capped;
            state.Channels[channel] = FailedLogonCursorLogic.NextSaved(read.LastRecordId, read.Capped, b.Newest);
            events.AddRange(read.Events);
            if (channel == FailedLogonEventReader.Security)
            {
                securityEvents.AddRange(read.Events);
                securityCapped = read.Capped;
            }
        }

        reset |= events.Any(e => e.Source == FailedLogonSource.LogCleared);
        state.LastWindowEndUtc = now;
        var lastCleared = securityReadable ? LatestClear(state, securityEvents, securityFresh, ct) : state.LastLogClearedUtc;
        state.LastLogClearedUtc = lastCleared;
        var (rdp, ssh, sql) = FailedLogonProtocolProbe.Read(ct);
        var auditFailure = FailedLogonAuditPolicy.ReadFailureEnabled();
        ct.ThrowIfCancellationRequested();
        var saveOk = true;
        // First run has nothing to lose: persist the baseline now so a failed first upload cannot skip events.
        if (commit && firstRun)
        {
            saveOk = SaveCursor(store, state);
            if (!saveOk)
                RetainBaseline(store, state);
        }
        var status = readable == 0 ? "unavailable" : failed > 0 || capped || !saveOk ? "partial" : "ok";
        var report = Build(status, start, now, reset, FailedLogonClassifier.Tally(events), rdp, ssh, sql, auditFailure);
        var feedStatus = !securityReadable ? "unavailable" : securityCapped || securityResetOrGap || !saveOk ? "partial" : "ok";
        // The look-back ends only with a staged window that carries it. A first run is saved before its upload and a
        // pass whose Security read failed reports no logons, so both look back again next time.
        if (lookbackRead && !firstRun && feedStatus != "unavailable")
            state.SuccessfulLogonsSeeded = true;
        if (commit && !firstRun)
            TryStage(generation, store, state, report);

        return new SecurityLogResult(
            report,
            feedStatus == "unavailable"
                ? SecurityLogFields.Unavailable
                : SecurityLogFields.SuccessfulLogons(feedStatus, Details<SuccessfulLogon>(lookback.Concat(securityEvents), FailedLogonSource.SuccessfulLogon4624)),
            securityReadable
                ? SecurityLogFields.LogCleared(feedStatus == "ok" ? "ok" : "partial", lastCleared)
                : lastCleared is null ? SecurityLogFields.Unavailable : SecurityLogFields.LogCleared("partial", lastCleared),
            SecurityLogFields.AdminChanges(feedStatus, Details<AdminGroupChange>(securityEvents, FailedLogonSource.GroupChange)));
    }

    /// <summary>
    /// Adds the successful logons of the last week up to <paramref name="upTo"/>, the record the window starts after.
    /// False when the log could not be read. A read cut short by its budget keeps the newest logons it found and counts
    /// as read: the next pass would scan the same newest records.
    /// </summary>
    private static bool LookBack(long upTo, List<FailedLogonEvent> into, CancellationToken ct)
    {
        if (FailedLogonEventReader.ReadRecentLogons(upTo, 2 * SecurityLogFields.MaxLogons, ct) is not { } recent)
            return false;
        into.AddRange(recent);
        return true;
    }

    /// <summary>A cursor file that still has no state continues from the retained first-run baseline; a file with state supersedes it.</summary>
    private static FailedLogonCursorState ApplyRetainedBaseline(FailedLogonCursorStore store, FailedLogonCursorState loaded, bool invalid)
    {
        if (invalid)
            return loaded;
        lock (Gate)
        {
            if (_baseline is not { } b || !ReferenceEquals(b.Store, store))
                return loaded;
            if (loaded.LastWindowEndUtc is not null)
            {
                _baseline = null;
                return loaded;
            }
            return Copy(b.State);
        }
    }

    private static void RetainBaseline(FailedLogonCursorStore store, FailedLogonCursorState state)
    {
        lock (Gate)
            _baseline = (store, Copy(state));
    }

    private static FailedLogonCursorState Copy(FailedLogonCursorState s) => new()
    {
        LastWindowEndUtc = s.LastWindowEndUtc,
        LastLogClearedUtc = s.LastLogClearedUtc,
        LogClearedSeeded = s.LogClearedSeeded,
        SuccessfulLogonsSeeded = s.SuccessfulLogonsSeeded,
        Channels = new Dictionary<string, long>(s.Channels, StringComparer.OrdinalIgnoreCase),
    };

    private static List<T> Details<T>(IEnumerable<FailedLogonEvent> events, FailedLogonSource source) where T : class
        => events.Where(e => e.Source == source).Select(e => e.Detail).OfType<T>().ToList();

    /// <summary>
    /// Newest of the saved value and the 1102 events of this scan. The reverse read for the newest 1102 still in the log
    /// runs only to seed a cursor that never did (first run, reset, gap, or no earlier scan); afterwards the forward
    /// scan sees every new 1102.
    /// </summary>
    private static DateTimeOffset? LatestClear(FailedLogonCursorState state, IEnumerable<FailedLogonEvent> securityEvents, bool fresh, CancellationToken ct)
    {
        var latest = state.LastLogClearedUtc;
        var candidates = securityEvents.Where(e => e.Source == FailedLogonSource.LogCleared).Select(e => (DateTimeOffset?)e.TimeUtc).ToList();
        if (fresh || !state.LogClearedSeeded)
        {
            var (ok, time) = FailedLogonEventReader.LatestSecurityCleared(ct);
            if (ok)
            {
                state.LogClearedSeeded = true;
                candidates.Add(time);
            }
        }
        foreach (var t in candidates)
            if (t is { } time && (latest is null || time > latest))
                latest = time;
        return latest;
    }

    /// <summary>Persists the cursor of the last committing collection; call after the snapshot upload succeeded.</summary>
    public static void CommitPending()
    {
        (FailedLogonCursorStore Store, FailedLogonCursorState State, object Report)? p;
        lock (Gate)
        {
            p = _pending;
            _pending = null;
        }
        if (p is { } pending && SaveCursor(pending.Store, pending.State))
        {
            lock (Gate)
            {
                if (_baseline is { } b && ReferenceEquals(b.Store, pending.Store))
                    _baseline = null;
            }
        }
    }

    /// <summary>Drops the pending cursor unless <paramref name="securityPayload"/> carries the report it was produced for.</summary>
    internal static void KeepPendingIfReported(object? securityPayload)
    {
        lock (Gate)
        {
            _generation++;
            if (_pending is { } p
                && !(securityPayload is IReadOnlyDictionary<string, object?> section
                     && section.TryGetValue("failed_logons", out var reported)
                     && ReferenceEquals(reported, p.Report)))
                _pending = null;
        }
    }

    internal static object Unavailable(DateTimeOffset now)
        => Build("unavailable", now, now, false, FailedLogonClassifier.Tally(Array.Empty<FailedLogonEvent>()), default, default, default);

    internal static object Build(
        string status,
        DateTimeOffset start,
        DateTimeOffset end,
        bool cursorReset,
        FailedLogonTally tally,
        ProtocolPresence rdp,
        ProtocolPresence ssh,
        ProtocolPresence sql,
        bool? auditFailureEnabled = null)
    {
        var groups = tally.Groups
            .Take(FailedLogonClassifier.GroupCap)
            .Select(g => new
            {
                protocol = g.Protocol,
                source_ip = g.SourceIp,
                count = g.Count,
                first_seen_utc = Iso(g.FirstSeenUtc),
                last_seen_utc = Iso(g.LastSeenUtc),
            })
            .ToArray();

        return new
        {
            status,
            window_start_utc = Iso(start),
            window_end_utc = Iso(end),
            cursor_reset = cursorReset,
            audit_failure_enabled = auditFailureEnabled,
            protocols = new
            {
                rdp = new { present = rdp.Present, listening = rdp.Listening, failed_count = tally.Counts["rdp"] },
                ssh = new { present = ssh.Present, listening = ssh.Listening, failed_count = tally.Counts["ssh"] },
                sql = new { present = sql.Present, listening = sql.Listening, failed_count = tally.Counts["sql"], unverified = tally.SqlUnverified },
                other = new { failed_count = tally.Counts["other"] },
            },
            reported_groups = groups,
            cap = FailedLogonClassifier.GroupCap,
            truncated = tally.Groups.Count > FailedLogonClassifier.GroupCap,
        };
    }

    internal static string Iso(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
}
