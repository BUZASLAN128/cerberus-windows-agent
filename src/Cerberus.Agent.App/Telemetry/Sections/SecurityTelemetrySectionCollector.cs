using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using Cerberus.Agent.Integrations.Ad;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class SecurityTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "security";

    private readonly FailedLogonCursorStore _cursor = new();
    private readonly bool _commitFailedLogons;

    public SecurityTelemetrySectionCollector()
        : this(commitFailedLogons: false)
    {
    }

    /// <param name="commitFailedLogons">True only for the scheduled snapshot path, whose upload success commits the
    /// failed-logon cursor (<see cref="WindowsTelemetryCollector.MarkSnapshotSubmitted"/>); other callers peek.</param>
    public SecurityTelemetrySectionCollector(bool commitFailedLogons)
    {
        _commitFailedLogons = commitFailedLogons;
    }

    public async ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var (domainJoined, domainName, adError) = AdStatusProbe.Probe();
        var now = DateTimeOffset.UtcNow;
        object failedLogons;
        try
        {
            failedLogons = await Task.Run(() => FailedLogonSection.Collect(_cursor, now, _commitFailedLogons, ct), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            failedLogons = FailedLogonSection.Unavailable(now);
        }
        return new
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
            failed_logons = failedLogons,
        };
    }
}
