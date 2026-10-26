namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

/// <summary>A successful interactive (2) or remote interactive (10) logon, Security 4624.</summary>
internal sealed record SuccessfulLogon(
    DateTimeOffset TimeUtc,
    string? User,
    string? Domain,
    int LogonType,
    string? SourceIp,
    string? WorkstationName,
    string? LogonId = null,
    string? LinkedLogonId = null);

/// <summary>A membership change of a privileged group, Security 4728/4729/4732/4733/4756/4757. SIDs and names only.</summary>
internal sealed record AdminGroupChange(
    int EventId,
    string Action,
    string? MemberName,
    string? MemberSid,
    string GroupSid,
    DateTimeOffset TimeUtc);

/// <summary>Turns the named data of a Security event into the typed detail carried by a <see cref="FailedLogonEvent"/>.</summary>
internal static class SecurityLogEventParser
{
    internal const string AdministratorsSid = "S-1-5-32-544";
    private const int MaxNameLength = 128;

    internal static FailedLogonEvent? Logon(DateTimeOffset time, IReadOnlyDictionary<string, string> data)
    {
        if (!int.TryParse(data.GetValueOrDefault("LogonType"), out var type) || type is not (2 or 10))
            return null;
        var user = Clean(data.GetValueOrDefault("TargetUserName"));
        // Session helper accounts are created for every interactive session and say nothing about a person.
        if (user is null
            || user.StartsWith("DWM-", StringComparison.OrdinalIgnoreCase)
            || user.StartsWith("UMFD-", StringComparison.OrdinalIgnoreCase))
            return null;
        var logon = new SuccessfulLogon(
            time,
            user,
            Clean(data.GetValueOrDefault("TargetDomainName")),
            type,
            FailedLogonClassifier.NormalizeIp(data.GetValueOrDefault("IpAddress")),
            Clean(data.GetValueOrDefault("WorkstationName")),
            Clean(data.GetValueOrDefault("TargetLogonId")),
            Clean(data.GetValueOrDefault("TargetLinkedLogonId")));
        return new FailedLogonEvent(FailedLogonSource.SuccessfulLogon4624, time, logon.SourceIp, type, Detail: logon);
    }

    internal static FailedLogonEvent? GroupChange(int eventId, DateTimeOffset time, IReadOnlyDictionary<string, string> data)
    {
        var action = eventId switch
        {
            4728 or 4732 or 4756 => "added",
            4729 or 4733 or 4757 => "removed",
            _ => null,
        };
        var groupSid = Clean(data.GetValueOrDefault("TargetSid"));
        if (action is null || groupSid is null || !IsPrivilegedGroup(eventId, groupSid))
            return null;
        var change = new AdminGroupChange(
            eventId,
            action,
            Clean(data.GetValueOrDefault("MemberName")),
            Clean(data.GetValueOrDefault("MemberSid")),
            groupSid,
            time);
        return new FailedLogonEvent(FailedLogonSource.GroupChange, time, null, Detail: change);
    }

    /// <summary>The builtin Administrators group; for domain-wide group events also Domain, Schema and Enterprise Admins (RID 512, 518, 519).</summary>
    internal static bool IsPrivilegedGroup(int eventId, string groupSid)
    {
        if (string.Equals(groupSid, AdministratorsSid, StringComparison.OrdinalIgnoreCase))
            return true;
        return eventId is 4728 or 4729 or 4756 or 4757
            && groupSid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
            && (groupSid.EndsWith("-512", StringComparison.Ordinal)
                || groupSid.EndsWith("-518", StringComparison.Ordinal)
                || groupSid.EndsWith("-519", StringComparison.Ordinal));
    }

    /// <summary>Trimmed value capped in length; null for empty values and the "-" placeholder.</summary>
    internal static string? Clean(string? raw)
    {
        var text = raw?.Trim();
        if (string.IsNullOrEmpty(text) || text == "-")
            return null;
        return text.Length > MaxNameLength ? text[..MaxNameLength] : text;
    }
}
