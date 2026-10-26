using System.ComponentModel;
using System.IO;
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
        var isDc = IsDomainController();

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
                        Kind(sid, info.SidUsage, machine, isDc)));
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

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PolicyAccountDomainInfo
    {
        public ushort NameLength;
        public ushort NameMaximumLength;
        public IntPtr NameBuffer;
        public IntPtr DomainSid;
    }

    private const int PolicyViewLocalInformation = 0x1;
    private const int PolicyAccountDomainInformation = 5;

    [DllImport("advapi32.dll")]
    private static extern uint LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes attributes, int access, out IntPtr policy);

    [DllImport("advapi32.dll")]
    private static extern uint LsaQueryInformationPolicy(IntPtr policy, int informationClass, out IntPtr buffer);

    [DllImport("advapi32.dll")]
    private static extern uint LsaFreeMemory(IntPtr buffer);

    [DllImport("advapi32.dll")]
    private static extern uint LsaClose(IntPtr policy);

    /// <summary>
    /// Account-domain SID of this machine from the LSA policy (the machine SID on a workgroup or member host, the
    /// domain SID on a domain controller); null when it cannot be read. Works on hosts where the computer name does not
    /// translate to a SID.
    /// </summary>
    private static SecurityIdentifier? MachineSid()
    {
        var attributes = new LsaObjectAttributes { Length = Marshal.SizeOf<LsaObjectAttributes>() };
        if (LsaOpenPolicy(IntPtr.Zero, ref attributes, PolicyViewLocalInformation, out var policy) != 0)
            return null;
        try
        {
            if (LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation, out var buffer) != 0 || buffer == IntPtr.Zero)
                return null;
            try
            {
                var info = Marshal.PtrToStructure<PolicyAccountDomainInfo>(buffer);
                return info.DomainSid == IntPtr.Zero ? null : new SecurityIdentifier(info.DomainSid);
            }
            catch (ArgumentException)
            {
                return null;
            }
            finally
            {
                LsaFreeMemory(buffer);
            }
        }
        finally
        {
            LsaClose(policy);
        }
    }

    /// <summary>Domain controllers have no local accounts: their account domain is the directory domain.</summary>
    private static bool IsDomainController()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ProductOptions");
            return string.Equals(key?.GetValue("ProductType") as string, "LanmanNT", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    /// <summary>
    /// local_* when the member SID has no account-domain part (builtin and well-known SIDs) or its account domain is the
    /// machine's; domain_* for any other domain, for Entra (S-1-12-1-*) accounts, and for every account domain on a
    /// domain controller. Computers, deleted and unresolved accounts are unknown, as are domain SIDs when the machine
    /// SID could not be read.
    /// </summary>
    internal static string Kind(SecurityIdentifier sid, int usage, SecurityIdentifier? machine, bool isDomainController = false)
    {
        var isUser = usage == SidTypeUser;
        if (!isUser && usage is not (SidTypeGroup or SidTypeAlias or SidTypeWellKnownGroup))
            return "unknown";
        var suffix = isUser ? "user" : "group";
        if (sid.Value.StartsWith("S-1-12-1-", StringComparison.Ordinal))
            return "domain_" + suffix;
        var domain = sid.AccountDomainSid;
        if (domain is null)
            return "local_" + suffix;
        if (isDomainController)
            return "domain_" + suffix;
        if (machine is null)
            return "unknown";
        return (domain.Equals(machine) ? "local_" : "domain_") + suffix;
    }
}
