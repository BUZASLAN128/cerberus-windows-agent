using System.IO;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

internal readonly record struct ProtocolPresence(bool Present, bool Listening);

/// <summary>Cheap presence/listening check for the RDP, SSH and SQL Server services.</summary>
internal static class FailedLogonProtocolProbe
{
    private const int DefaultRdpPort = 3389;
    private const int DefaultSshPort = 22;
    private const int DefaultSqlPort = 1433;

    public static (ProtocolPresence Rdp, ProtocolPresence Ssh, ProtocolPresence Sql) Read(CancellationToken ct)
    {
        var services = ReadServiceNames();
        var tcp = ReadTcpPorts();
        var owners = ListenerOwners(ct);

        var rdp = new ProtocolPresence(services.Contains("TermService"), RdpListening(tcp, ReadRdpPort(), owners));
        var ssh = new ProtocolPresence(
            services.Contains("sshd"),
            // Any sshd-owned listener counts whatever its port; port 22 only when the owners cannot be read.
            owners?.Any(o => IsProcess(o.Name, "sshd")) ?? tcp.Contains(DefaultSshPort));
        var sqlPresent = services.Any(FailedLogonEventReader.IsSqlProvider);
        var sql = new ProtocolPresence(
            sqlPresent,
            // Any sqlservr-owned listener counts whatever its port; otherwise 1433 must not be held by another process.
            sqlPresent && (owners?.Any(o => IsProcess(o.Name, "sqlservr")) == true || PortOwned(tcp, DefaultSqlPort, owners, "sqlservr")));
        return (rdp, ssh, sql);
    }

    /// <summary>
    /// RDP is listening when the configured port is open. With readable owners it must be held by svchost (the
    /// TermService host; the owner lookup reports image names only) or by a process whose name could not be read;
    /// another process on that port is not RDP. No owner row for the port falls back to the port check.
    /// </summary>
    internal static bool RdpListening(HashSet<int> tcp, int port, IReadOnlyList<(int Port, string? Name)>? owners)
        => PortOwned(tcp, port, owners, "svchost");

    /// <summary>
    /// Port check refined by owners: with owner rows for the port one must be <paramref name="expected"/> or unnamed;
    /// no rows or unreadable owners fall back to the port being open.
    /// </summary>
    internal static bool PortOwned(HashSet<int> tcp, int port, IReadOnlyList<(int Port, string? Name)>? owners, string expected)
    {
        var rows = owners?.Where(o => o.Port == port).ToList();
        return rows is null or { Count: 0 }
            ? tcp.Contains(port)
            : rows.Any(o => o.Name is null || IsProcess(o.Name, expected));
    }

    private static bool IsProcess(string? name, string expected) => string.Equals(name, expected, StringComparison.OrdinalIgnoreCase);

    /// <summary>Presence reporting: an unreadable service list counts as no services.</summary>
    internal static HashSet<string> ReadServiceNames()
        => TryReadServiceNames() ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Service names, or null when the service list cannot be read.</summary>
    internal static HashSet<string>? TryReadServiceNames()
    {
        try
        {
            return ServiceController.GetServices().Select(s =>
            {
                using (s)
                    return s.ServiceName;
            }).ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    private static HashSet<int> ReadTcpPorts()
    {
        try
        {
            return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(e => e.Port).ToHashSet();
        }
        catch (NetworkInformationException)
        {
            return new HashSet<int>();
        }
    }

    /// <summary>Port and owning process name (null when unreadable) of every TCP listener; null when the owner lookup fails.</summary>
    private static List<(int Port, string? Name)>? ListenerOwners(CancellationToken ct)
    {
        try
        {
            return PortsNative.Read(ct)
                .Where(p => p.Protocol == "tcp")
                .Select(p => (p.Port, p.ProcessName))
                .ToList();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static int ReadRdpPort()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            if (key?.GetValue("PortNumber") is int port && port is > 0 and < 65536)
                return port;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
        }
        return DefaultRdpPort;
    }
}
