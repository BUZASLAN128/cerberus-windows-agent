using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal static class WindowsLocalUsersProbe
{
    private const int ErrorMoreData = 234;
    private const int PreferredPageBytes = 64 * 1024;
    private const uint FilterNormalAccount = 2;
    private const uint AccountDisabled = 0x0002;
    private const uint AccountLocked = 0x0010;

    internal static LocalAccountUserRead Read(SecurityIdentifier? machine, CancellationToken ct)
    {
        if (machine is null)
            throw new InvalidOperationException("Local account domain unavailable.");

        var entries = new List<LocalAccountItem>(LocalAccountsProbe.MaxUsers);
        var total = 0;
        var resume = 0u;
        var incomplete = false;
        do
        {
            ct.ThrowIfCancellationRequested();
            var rc = NetUserEnum(null, 3, FilterNormalAccount, out var buffer, PreferredPageBytes, out var read, out _, ref resume);
            try
            {
                if (rc is not (0 or ErrorMoreData))
                    throw new Win32Exception(rc);

                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var size = Marshal.SizeOf<UserInfo3>();
                var keep = Math.Min(read, LocalAccountsProbe.MaxUsers - entries.Count);
                for (var i = 0; i < keep; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    var info = Marshal.PtrToStructure<UserInfo3>(buffer + i * size);
                    var name = Marshal.PtrToStringUni(info.Name);
                    if (string.IsNullOrEmpty(name) || info.UserId == 0)
                        throw new InvalidOperationException("Incomplete local user entry.");

                    entries.Add(new LocalAccountItem(LocalAccountsProbe.CleanText(name),
                        FormattableString.Invariant($"{machine.Value}-{info.UserId}"),
                        (info.Flags & AccountDisabled) == 0, (info.Flags & AccountLocked) != 0,
                        FormatTime(info.LastLogon), PasswordLastSet(now, info.PasswordAge), []));
                }
                total = checked(total + read);

                if (rc == 0)
                    break;
                if (resume == 0 || read == 0)
                {
                    incomplete = true;
                    break;
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    LocalAdminsProbe.NetApiBufferFree(buffer);
            }
        } while (true);

        // The resume hint is approximate. Only report a count after walking all pages successfully.
        var truncated = entries.Count < total || incomplete;
        var warnedGroups = false;
        for (var i = 0; i < entries.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var (groups, more) = ReadDirectGroups(entries[i].Name, ct);
                entries[i] = entries[i] with { Groups = groups };
                truncated |= more;
            }
            catch (Win32Exception ex)
            {
                if (!warnedGroups)
                    LocalAccountsTelemetrySectionCollector.WarnProbe("direct_groups", ex);
                warnedGroups = true;
            }
        }

        return new LocalAccountUserRead(new LocalAccountUsers(incomplete ? null : total, truncated,
            entries.OrderBy(item => item.Sid, StringComparer.Ordinal).ToArray()), incomplete || warnedGroups);
    }

    private static (string[] Groups, bool Truncated) ReadDirectGroups(string name, CancellationToken ct)
    {
        // Flags of zero exclude membership through nested global groups.
        var rc = NetUserGetLocalGroups(null, name, 0, 0, out var buffer, PreferredPageBytes, out var read, out var total);
        try
        {
            if (rc is not (0 or ErrorMoreData))
                throw new Win32Exception(rc);
            var groups = new string[read];
            for (var i = 0; i < groups.Length; i++)
            {
                ct.ThrowIfCancellationRequested();
                var group = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size)) ?? "";
                groups[i] = LocalAccountsProbe.CleanText(group);
            }
            var retained = SortAndCapDirectGroups(groups);
            return (retained, rc == ErrorMoreData || total > retained.Length || read > retained.Length);
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                LocalAdminsProbe.NetApiBufferFree(buffer);
        }
    }

    internal static string? FormatTime(long unixSeconds)
        => unixSeconds <= 0 || unixSeconds == uint.MaxValue ? null
            : DateTimeOffset.FromUnixTimeSeconds(unixSeconds).UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    internal static string? PasswordLastSet(long now, uint passwordAge)
    {
        var lastSet = now - passwordAge;
        return passwordAge == uint.MaxValue || lastSet == uint.MaxValue
            ? null : FormatTime(lastSet - lastSet % 60);
    }

    internal static string[] SortAndCapDirectGroups(string[] groups)
    {
        Array.Sort(groups, StringComparer.OrdinalIgnoreCase);
        return groups.Length > LocalAccountsProbe.MaxDirectGroups ? groups[..LocalAccountsProbe.MaxDirectGroups] : groups;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UserInfo3
    {
        public IntPtr Name;
        public IntPtr Password;
        public uint PasswordAge;
        public uint Privilege;
        public IntPtr HomeDirectory;
        public IntPtr Comment;
        public uint Flags;
        public IntPtr ScriptPath;
        public uint AuthorizationFlags;
        public IntPtr FullName;
        public IntPtr UserComment;
        public IntPtr Parameters;
        public IntPtr Workstations;
        public uint LastLogon;
        public uint LastLogoff;
        public uint AccountExpires;
        public uint MaxStorage;
        public uint UnitsPerWeek;
        public IntPtr LogonHours;
        public uint BadPasswordCount;
        public uint LogonCount;
        public IntPtr LogonServer;
        public uint CountryCode;
        public uint CodePage;
        public uint UserId;
        public uint PrimaryGroupId;
        public IntPtr Profile;
        public IntPtr HomeDirectoryDrive;
        public uint PasswordExpired;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserEnum(string? serverName, uint level, uint filter, out IntPtr buffer,
        int preferredMaxLength, out int entriesRead, out int totalEntries, ref uint resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetLocalGroups(string? serverName, string userName, uint level, uint flags,
        out IntPtr buffer, int preferredMaxLength, out int entriesRead, out int totalEntries);
}
