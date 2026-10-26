namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

/// <summary>
/// Everything one committing or peeking pass over the logs yields. <see cref="FailedLogons"/> is the object the pending
/// cursor is bound to; the other fields come from the same scan and window and are reported or dropped with it.
/// </summary>
internal sealed record SecurityLogResult(
    object FailedLogons,
    object SuccessfulLogons,
    object LogCleared,
    AdminChangeReport AdminChanges)
{
    internal static SecurityLogResult Unavailable(DateTimeOffset now) => new(
        FailedLogonSection.Unavailable(now),
        SecurityLogFields.Unavailable,
        SecurityLogFields.Unavailable,
        new AdminChangeReport("unavailable", null));
}

/// <summary>Window status of the group-change feed and the <c>changes</c> object built from it (null when unavailable).</summary>
internal sealed record AdminChangeReport(string Status, object? Changes);

/// <summary>Builders for the consume-once fields derived from the Security scan and for <c>local_admins</c>.</summary>
internal static class SecurityLogFields
{
    internal const int MaxLogons = 50;
    internal const int MaxChanges = 20;

    internal static readonly object Unavailable = new { status = "unavailable" };

    /// <summary>Latest <see cref="MaxLogons"/> logons (newest first) plus the window total.</summary>
    internal static object SuccessfulLogons(string status, IReadOnlyList<SuccessfulLogon> all)
    {
        var logons = DedupeLinkedLogons(all);
        return new
        {
            status,
            count = logons.Count,
            truncated = logons.Count > MaxLogons,
            items = logons
                .OrderByDescending(l => l.TimeUtc)
                .Take(MaxLogons)
                .Select(l => new
                {
                    time_utc = FailedLogonSection.Iso(l.TimeUtc),
                    user = l.User,
                    domain = l.Domain,
                    logon_type = l.LogonType,
                    source_ip = l.SourceIp,
                    workstation_name = l.WorkstationName,
                })
                .ToArray(),
        };
    }

    /// <summary>
    /// An admin logon under UAC writes two 4624 events (limited and elevated token) that reference each other through
    /// TargetLogonId / TargetLinkedLogonId. Of such a pair with the same user, domain, type and address only the first
    /// in input order is kept. Input order is otherwise preserved.
    /// </summary>
    internal static IReadOnlyList<SuccessfulLogon> DedupeLinkedLogons(IReadOnlyList<SuccessfulLogon> logons)
    {
        var keptById = new Dictionary<string, SuccessfulLogon>(StringComparer.OrdinalIgnoreCase);
        var keptByLink = new Dictionary<string, SuccessfulLogon>(StringComparer.OrdinalIgnoreCase);
        var result = new List<SuccessfulLogon>(logons.Count);
        foreach (var l in logons)
        {
            var id = RealLogonId(l.LogonId);
            var link = RealLogonId(l.LinkedLogonId);
            if ((link is not null && keptById.TryGetValue(link, out var a) && SameSession(a, l))
                || (id is not null && keptByLink.TryGetValue(id, out var b) && SameSession(b, l)))
                continue;
            result.Add(l);
            if (id is not null)
                keptById[id] = l;
            if (link is not null)
                keptByLink[link] = l;
        }
        return result;
    }

    private static string? RealLogonId(string? id)
        => id is null || id.Trim('0', 'x', 'X').Length == 0 ? null : id;

    private static bool SameSession(SuccessfulLogon a, SuccessfulLogon b)
        => a.LogonType == b.LogonType
           && string.Equals(a.User, b.User, StringComparison.OrdinalIgnoreCase)
           && string.Equals(a.Domain, b.Domain, StringComparison.OrdinalIgnoreCase)
           && string.Equals(a.SourceIp, b.SourceIp, StringComparison.Ordinal);

    internal static AdminChangeReport AdminChanges(string status, IReadOnlyList<AdminGroupChange> changes)
        => new(status, new
        {
            count = changes.Count,
            truncated = changes.Count > MaxChanges,
            items = changes
                .OrderByDescending(c => c.TimeUtc)
                .Take(MaxChanges)
                .Select(c => new
                {
                    event_id = c.EventId,
                    action = c.Action,
                    member_name = c.MemberName,
                    member_sid = c.MemberSid,
                    group_sid = c.GroupSid,
                    time_utc = FailedLogonSection.Iso(c.TimeUtc),
                })
                .ToArray(),
        });

    internal static object LogCleared(string status, DateTimeOffset? lastClearedUtc)
        => new { status, last_cleared_utc = lastClearedUtc is { } t ? FailedLogonSection.Iso(t) : null };

    /// <summary>
    /// <c>local_admins</c>: ok when members and the change feed are both complete, unavailable when neither could be
    /// read, partial otherwise (including an incomplete member list or a change feed that is partial because the
    /// Security log was cleared, wrapped or capped). A capped member list stays ok with truncated.
    /// </summary>
    internal static object LocalAdmins(LocalAdminsRead? members, AdminChangeReport changes)
    {
        var membersOk = members is not null;
        var changesOk = changes.Status == "ok";
        var status = !membersOk && changes.Status == "unavailable" ? "unavailable"
            : membersOk && changesOk && !members!.Incomplete ? "ok"
            : "partial";
        return new
        {
            status,
            count = members?.Total ?? 0,
            members = (members?.Members ?? Array.Empty<LocalAdminMember>())
                .Select(m => new { name = m.Name, sid = m.Sid, kind = m.Kind })
                .ToArray(),
            truncated = members?.Truncated ?? false,
            changes = changes.Changes ?? new { count = 0, truncated = false, items = Array.Empty<object>() },
        };
    }
}
