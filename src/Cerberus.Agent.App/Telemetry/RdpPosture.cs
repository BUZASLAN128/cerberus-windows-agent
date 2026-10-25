using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry;

/// <summary>Remote Desktop settings shared by the rdp section and sessions.rdp_posture. Null means unreadable.</summary>
internal sealed record RdpPosture(bool? RemoteDesktopEnabled, bool? NlaRequired, int? PortNumber)
{
    internal static readonly RdpPosture Unknown = new(null, null, null);

    private const string TerminalServerKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string RdpTcpKey = TerminalServerKey + @"\WinStations\RDP-Tcp";

    internal static RdpPosture Read() => From(
        TelemetryValue.ReadDword(Registry.LocalMachine, TerminalServerKey, "fDenyTSConnections"),
        TelemetryValue.ReadDword(Registry.LocalMachine, RdpTcpKey, "UserAuthentication"),
        TelemetryValue.ReadDword(Registry.LocalMachine, RdpTcpKey, "PortNumber"));

    internal static RdpPosture From(int? denyTsConnections, int? userAuthentication, int? portNumber) => new(
        denyTsConnections.HasValue ? denyTsConnections.Value == 0 : null,
        userAuthentication.HasValue ? userAuthentication.Value == 1 : null,
        portNumber);

    internal object ToPayload() => new
    {
        remote_desktop_enabled = RemoteDesktopEnabled,
        nla_required = NlaRequired,
        port_number = PortNumber,
    };
}
