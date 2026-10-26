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
    internal static object SuccessfulLogons(string status, IReadOnlyList<SuccessfulLogon> logons)
        => new
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
    /// read, partial otherwise (including an incomplete member list). A capped member list stays ok with truncated.
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
