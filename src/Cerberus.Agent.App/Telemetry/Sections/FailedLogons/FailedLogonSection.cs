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

    public static object Collect(FailedLogonCursorStore store, DateTimeOffset now, bool commit, CancellationToken ct)
    {
        lock (Gate)
        {
            if (commit)
                _pending = null;
            var state = store.Load(out var invalid);
            var firstRun = !invalid && state.LastWindowEndUtc is null;
            var start = state.LastWindowEndUtc is { } prev && prev <= now ? prev : now;
            var events = new List<FailedLogonEvent>();
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
                    continue;
                }

                var read = FailedLogonEventReader.Read(channel, after, ct);
                if (read.Failed)
                {
                    failed++;
                    continue;
                }
                readable++;
                capped |= read.Capped;
                state.Channels[channel] = FailedLogonCursorLogic.NextSaved(read.LastRecordId, read.Capped, b.Newest);
                events.AddRange(read.Events);
            }

            reset |= events.Any(e => e.Source == FailedLogonSource.LogCleared);
            state.LastWindowEndUtc = now;
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
            return report;
        }
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
