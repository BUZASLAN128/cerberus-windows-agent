using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

internal sealed record LocalAdminMember(string Name, string Sid, string Kind);

/// <summary>Members of the builtin Administrators group, capped; <see cref="Total"/> counts every member.</summary>
internal sealed record LocalAdminsRead(IReadOnlyList<LocalAdminMember> Members, int Total, bool Truncated, bool Incomplete);

/// <summary>
/// Reads the builtin Administrators group (S-1-5-32-544) with <c>NetLocalGroupGetMembers</c> level 2. The group is
/// found by SID and its current name looked up, so a renamed or localized group works. Names and SIDs only.
/// </summary>
internal static class LocalAdminsProbe
{
    internal const int MaxMembers = 100;
    private const int NerrSuccess = 0;
    private const int ErrorMoreData = 234;
    private const int MaxPreferredLength = -1;

    private const int SidTypeUser = 1;
    private const int SidTypeGroup = 2;
    private const int SidTypeAlias = 4;
    private const int SidTypeWellKnownGroup = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct LocalGroupMembersInfo2
    {
        public IntPtr Sid;
        public int SidUsage;
        public IntPtr DomainAndName;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(
        string? serverName,
        string localGroupName,
        int level,
        out IntPtr buffer,
        int preferredMaxLength,
        out int entriesRead,
        out int totalEntries,
        ref IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    /// <exception cref="Win32Exception">The group name lookup or the member enumeration failed.</exception>
    public static LocalAdminsRead Read(CancellationToken ct)
    {
        var groupSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var account = groupSid.Translate(typeof(NTAccount)).Value;
        var groupName = account[(account.LastIndexOf('\\') + 1)..];
        var machine = MachineSid();

        var members = new List<LocalAdminMember>();
        var resume = IntPtr.Zero;
        var incomplete = false;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var rc = NetLocalGroupGetMembers(null, groupName, 2, out var buffer, MaxPreferredLength, out var read, out _, ref resume);
            try
            {
                if (rc is not (NerrSuccess or ErrorMoreData))
                    throw new Win32Exception(rc);
                var size = Marshal.SizeOf<LocalGroupMembersInfo2>();
                for (var i = 0; i < read; i++)
                {
                    var info = Marshal.PtrToStructure<LocalGroupMembersInfo2>(buffer + i * size);
                    var sid = new SecurityIdentifier(info.Sid);
                    members.Add(new LocalAdminMember(
                        SecurityLogEventParser.Clean(Marshal.PtrToStringUni(info.DomainAndName)) ?? sid.Value,
                        sid.Value,
                        Kind(sid, info.SidUsage, machine)));
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    NetApiBufferFree(buffer);
            }
            if (rc != ErrorMoreData)
                break;
            if (resume == IntPtr.Zero)
            {
                incomplete = true;
                break;
            }
        }

        var ordered = members.OrderBy(m => m.Sid, StringComparer.Ordinal).ToList();
        return new LocalAdminsRead(ordered.Take(MaxMembers).ToList(), ordered.Count, ordered.Count > MaxMembers, incomplete);
    }

    /// <summary>Domain SID of this machine's local accounts, or null when it cannot be resolved.</summary>
    private static SecurityIdentifier? MachineSid()
    {
        try
        {
            return new NTAccount(Environment.MachineName).Translate(typeof(SecurityIdentifier)) as SecurityIdentifier;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException or ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    /// local_* when the member SID's domain part is the machine's (builtin and well-known SIDs have none and are local),
    /// domain_* for any other domain; computers, deleted and unresolved accounts are unknown.
    /// </summary>
    internal static string Kind(SecurityIdentifier sid, int usage, SecurityIdentifier? machine)
    {
        var isUser = usage == SidTypeUser;
        if (!isUser && usage is not (SidTypeGroup or SidTypeAlias or SidTypeWellKnownGroup))
            return "unknown";
        var domain = sid.AccountDomainSid;
        bool local;
        if (domain is null)
            local = true;
        else if (machine is null)
            return "unknown";
        else
            local = domain.Equals(machine);
        return (local ? "local_" : "domain_") + (isUser ? "user" : "group");
    }
}
