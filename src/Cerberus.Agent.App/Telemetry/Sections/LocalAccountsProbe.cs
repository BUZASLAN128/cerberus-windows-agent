using System.Text;
using System.Text.Json.Serialization;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed record LocalAccountItem(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("sid")] string Sid,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("locked")] bool? Locked,
    [property: JsonPropertyName("last_logon_utc")] string? LastLogonUtc,
    [property: JsonPropertyName("password_last_set_utc")] string? PasswordLastSetUtc,
    [property: JsonPropertyName("groups")] IReadOnlyList<string> Groups);

internal sealed record LocalAccountUsers(
    [property: JsonPropertyName("count")] int? Count,
    [property: JsonPropertyName("truncated")] bool Truncated,
    [property: JsonPropertyName("items")] IReadOnlyList<LocalAccountItem> Items);

internal sealed record LocalAccountUserRead(LocalAccountUsers Users, bool Incomplete);

internal static class LocalAccountsProbe
{
    internal const int MaxUsers = 500;
    internal const int MaxDirectGroups = 32;
    private const int MaxText = 256;

    internal static readonly IReadOnlyList<(string Id, string Sid)> PrivilegedGroups = Array.AsReadOnly(new[]
    {
        ("administrators", LocalAdminsProbe.AdministratorsSid),
        ("remote_desktop_users", "S-1-5-32-555"),
        ("backup_operators", "S-1-5-32-551"),
        ("remote_management_users", "S-1-5-32-580"),
        ("power_users", "S-1-5-32-547"),
        ("hyper_v_administrators", "S-1-5-32-578"),
    });

    internal static object Read(WindowsTelemetryContext context, CancellationToken ct)
    {
        var isDc = LocalAdminsProbe.ReadDomainController();
        if (isDc is null)
            return AgentSnapshotFactory.UnavailableLocalAccounts;

        ct.ThrowIfCancellationRequested();
        var machine = LocalAdminsProbe.MachineSid();
        return Collect(isDc.Value, () => WindowsLocalUsersProbe.Read(machine, ct), sid =>
            sid == LocalAdminsProbe.AdministratorsSid
                ? LocalAdminsProbe.Server.ReadGroupAsync(context, ct, machine, isDc).GetAwaiter().GetResult()
                : LocalAdminsProbe.ReadGroup(sid, machine, isDc.Value, LocalAdminsProbe.MaxPrivilegedMembers, ct), ct);
    }

    internal static object Collect(bool isDomainController, Func<LocalAccountUserRead> readUsers,
        Func<string, LocalGroupRead?> readGroup, CancellationToken ct)
    {
        var users = new LocalAccountUsers(null, false, []);
        var partial = false;
        if (!isDomainController)
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                var read = readUsers();
                users = read.Users;
                partial = read.Incomplete || users.Truncated;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LocalAccountsTelemetrySectionCollector.WarnProbe("users", ex);
                partial = true;
            }
        }

        var groups = new List<object>(PrivilegedGroups.Count);
        foreach (var (id, sid) in PrivilegedGroups)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (readGroup(sid) is not { } group)
                    continue;

                var membership = group.Membership;
                if (membership.Incomplete)
                {
                    // The wire count is required for a group. An unfinished read cannot supply it.
                    partial = true;
                    continue;
                }

                partial |= membership.Truncated;
                groups.Add(new
                {
                    id,
                    name = CleanText(group.Name),
                    count = membership.Total,
                    truncated = membership.Truncated,
                    members = membership.Members.Select(member => new
                    {
                        name = CleanText(member.Name),
                        sid = member.Sid,
                        kind = member.Kind,
                    }).ToArray(),
                });
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LocalAccountsTelemetrySectionCollector.WarnProbe(id, ex);
                partial = true;
            }
        }

        if (!isDomainController && users.Count is null && users.Items.Count == 0 && groups.Count == 0)
            return AgentSnapshotFactory.UnavailableLocalAccounts;

        return new
        {
            status = isDomainController ? "domain_controller" : partial ? "partial" : "ok",
            users,
            privileged_groups = groups,
        };
    }

    internal static string CleanText(string text)
    {
        if (text.Length <= MaxText && !text.Contains('\0') && !text.Any(char.IsSurrogate))
            return text;

        var cleaned = new StringBuilder(MaxText);
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.Value == 0)
                continue;
            if (cleaned.Length + rune.Utf16SequenceLength > MaxText)
                break;
            cleaned.Append(rune.ToString());
        }
        return cleaned.ToString();
    }
}
