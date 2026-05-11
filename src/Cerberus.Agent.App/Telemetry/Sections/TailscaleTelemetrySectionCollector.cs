using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class TailscaleTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "tailscale";

    public async ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var (installed, connected, snapshot, err) = await TailscaleStatusProbe
            .ProbeAsync(timeout: TimeSpan.FromSeconds(5), ct: ct)
            .ConfigureAwait(false);

        return new
        {
            status = installed ? "ok" : "unavailable",
            installed,
            connected,
            error = Sanitizer.Redact(err),
            snapshot,
        };
    }
}
