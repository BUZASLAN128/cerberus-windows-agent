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
        var sqlOwned = AnySqlListener(ct);

        var rdp = new ProtocolPresence(
            services.Contains("TermService"),
            tcp.Contains(ReadRdpPort()));
        var ssh = new ProtocolPresence(
            services.Contains("sshd"),
            tcp.Contains(DefaultSshPort));
        var sqlPresent = services.Any(FailedLogonEventReader.IsSqlProvider);
        var sql = new ProtocolPresence(
            sqlPresent,
            sqlPresent && (tcp.Contains(DefaultSqlPort) || sqlOwned));
        return (rdp, ssh, sql);
    }

    internal static HashSet<string> ReadServiceNames()
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
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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

    /// <summary>True when any TCP listener is owned by the sqlservr process.</summary>
    private static bool AnySqlListener(CancellationToken ct)
    {
        try
        {
            return PortsNative.Read(ct).Any(p =>
                p.Protocol == "tcp" && string.Equals(p.ProcessName, "sqlservr", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            return false;
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
