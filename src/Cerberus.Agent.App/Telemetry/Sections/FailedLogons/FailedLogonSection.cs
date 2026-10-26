namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

/// <summary>
/// Builds the <c>security.failed_logons</c> object. Each collection reports the window since the last committed
/// one (<c>window_start_utc</c> = last committed window end). The very first run has no history: it starts at the
/// current end of every log, reports zeros and is not a cursor reset. A reset (cleared log, regressed record id,
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
    private static readonly object Gate = new();
    private static (FailedLogonCursorStore Store, FailedLogonCursorState State, object Report)? _pending;

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
        lock (Gate)
        {
            if (commit)
                _pending = null;
            var state = store.Load(out var invalid);
            var firstRun = !invalid && state.LastWindowEndUtc is null;
            var start = state.LastWindowEndUtc is { } prev && prev <= now ? prev : now;
            var events = new List<FailedLogonEvent>();
            var securityEvents = new List<FailedLogonEvent>();
            var securityReadable = false;
            var securityCapped = false;
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
                var after = FailedLogonCursorLogic.StartAfter(decision, saved, b.Oldest, b.Newest);
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
            var lastCleared = securityReadable ? LatestClear(state.LastLogClearedUtc, securityEvents) : state.LastLogClearedUtc;
            state.LastLogClearedUtc = lastCleared;
            var (rdp, ssh, sql) = FailedLogonProtocolProbe.Read(ct);
            var auditFailure = FailedLogonAuditPolicy.ReadFailureEnabled();
            ct.ThrowIfCancellationRequested();
            var saveOk = true;
            // First run has nothing to lose: persist the baseline now so a failed first upload cannot skip events.
            if (commit && firstRun)
                saveOk = store.Save(state);
            var status = readable == 0 ? "unavailable" : failed > 0 || capped || !saveOk ? "partial" : "ok";
            var report = Build(status, start, now, reset, FailedLogonClassifier.Tally(events), rdp, ssh, sql, auditFailure);
            if (commit && !firstRun)
                _pending = (store, state, report);

            var feedStatus = !securityReadable ? "unavailable" : securityCapped || !saveOk ? "partial" : "ok";
            return new SecurityLogResult(
                report,
                feedStatus == "unavailable"
                    ? SecurityLogFields.Unavailable
                    : SecurityLogFields.SuccessfulLogons(feedStatus, Details<SuccessfulLogon>(securityEvents, FailedLogonSource.SuccessfulLogon4624)),
                securityReadable
                    ? SecurityLogFields.LogCleared(feedStatus == "ok" ? "ok" : "partial", lastCleared)
                    : lastCleared is null ? SecurityLogFields.Unavailable : SecurityLogFields.LogCleared("partial", lastCleared),
                SecurityLogFields.AdminChanges(feedStatus, Details<AdminGroupChange>(securityEvents, FailedLogonSource.GroupChange)));
        }
    }

    private static List<T> Details<T>(IEnumerable<FailedLogonEvent> events, FailedLogonSource source) where T : class
        => events.Where(e => e.Source == source).Select(e => e.Detail).OfType<T>().ToList();

    /// <summary>Newest of the saved value, the 1102 events of this scan and the newest 1102 still in the Security log.</summary>
    private static DateTimeOffset? LatestClear(DateTimeOffset? saved, IEnumerable<FailedLogonEvent> securityEvents)
    {
        var latest = saved;
        foreach (var t in securityEvents.Where(e => e.Source == FailedLogonSource.LogCleared).Select(e => (DateTimeOffset?)e.TimeUtc)
                     .Append(FailedLogonEventReader.LatestSecurityCleared()))
            if (t is { } time && (latest is null || time > latest))
                latest = time;
        return latest;
    }

    /// <summary>Persists the cursor of the last committing collection; call after the snapshot upload succeeded.</summary>
    public static void CommitPending()
    {
        lock (Gate)
        {
            if (_pending is { } p)
                p.Store.Save(p.State);
            _pending = null;
        }
    }

    /// <summary>Drops the pending cursor unless <paramref name="securityPayload"/> carries the report it was produced for.</summary>
    internal static void KeepPendingIfReported(object? securityPayload)
    {
        lock (Gate)
        {
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
                sql = new { present = sql.Present, listening = sql.Listening, failed_count = tally.Counts["sql"] },
                other = new { failed_count = tally.Counts["other"] },
            },
            reported_groups = groups,
            cap = FailedLogonClassifier.GroupCap,
            truncated = tally.Groups.Count > FailedLogonClassifier.GroupCap,
        };
    }

    internal static string Iso(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
}
