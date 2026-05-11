using Cerberus.Agent.Integrations.Ad;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class SecurityTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "security";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var (domainJoined, domainName, adError) = AdStatusProbe.Probe();
        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            defender = TelemetryValue.ReadService("WinDefend"),
            bitlocker = TelemetryValue.ReadService("BDESVC"),
            windows_update = TelemetryValue.ReadService("wuauserv"),
            ad = new
            {
                domain_joined = domainJoined,
                domain_name = domainName,
                error = Sanitizer.Redact(adError),
            },
        });
    }
}
