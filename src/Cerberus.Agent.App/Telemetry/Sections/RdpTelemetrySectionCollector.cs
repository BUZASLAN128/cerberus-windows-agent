using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class RdpTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "rdp";

    public async ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var posture = RdpPosture.Read();
        var portNumber = posture.PortNumber;
        var portProbe = await ProbeLocalRdpPortAsync(portNumber, ct).ConfigureAwait(false);

        return new
        {
            status = "ok",
            service = TelemetryValue.ReadService("TermService"),
            port_number = portNumber,
            remote_desktop_enabled = posture.RemoteDesktopEnabled,
            nla_required = posture.NlaRequired,
            credential_probe_performed = false,
            port_probe = portProbe,
            port_probe_status = portProbe.Status,
            port_listening_local = portProbe.Reachable,
            port_probe_latency_ms = portProbe.LatencyMs,
        };
    }

    internal static async Task<RdpPortProbeResult> ProbeLocalRdpPortAsync(int? portNumber, CancellationToken ct)
    {
        if (!portNumber.HasValue || portNumber.Value is < 1 or > 65535)
            return new RdpPortProbeResult("skipped", null, null, "missing_or_invalid_port");

        var port = portNumber.Value;
        var watch = Stopwatch.StartNew();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(900));
            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token).ConfigureAwait(false);
            watch.Stop();
            return new RdpPortProbeResult("reachable", true, (int)Math.Min(watch.ElapsedMilliseconds, int.MaxValue), null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            watch.Stop();
            return new RdpPortProbeResult("timeout", false, (int)Math.Min(watch.ElapsedMilliseconds, int.MaxValue), "timeout");
        }
        catch (SocketException ex)
        {
            watch.Stop();
            return new RdpPortProbeResult("closed", false, (int)Math.Min(watch.ElapsedMilliseconds, int.MaxValue), ex.SocketErrorCode.ToString());
        }
        catch (Exception ex)
        {
            watch.Stop();
            return new RdpPortProbeResult("error", false, (int)Math.Min(watch.ElapsedMilliseconds, int.MaxValue), ex.GetType().Name);
        }
    }

    internal sealed record RdpPortProbeResult(string Status, bool? Reachable, int? LatencyMs, string? Error);
}
