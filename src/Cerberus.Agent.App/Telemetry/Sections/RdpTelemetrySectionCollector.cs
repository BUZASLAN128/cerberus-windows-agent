using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class RdpTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "rdp";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var rdpDenied = TelemetryValue.ReadDword(
            Registry.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections");
        var nla = TelemetryValue.ReadDword(
            Registry.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication");
        var portNumber = TelemetryValue.ReadDword(
            Registry.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "PortNumber");

        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            service = TelemetryValue.ReadService("TermService"),
            port_number = portNumber,
            remote_desktop_enabled = rdpDenied.HasValue ? (bool?)(rdpDenied.Value == 0) : null,
            nla_required = nla.HasValue ? (bool?)(nla.Value == 1) : null,
            credential_probe_performed = false,
        });
    }
}
