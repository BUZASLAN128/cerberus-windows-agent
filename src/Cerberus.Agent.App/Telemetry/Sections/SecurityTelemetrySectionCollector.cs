using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class SecurityTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "security";

    private readonly FailedLogonCursorStore? _cursor;
    private readonly bool _commitFailedLogons;

    public SecurityTelemetrySectionCollector()
        : this(commitFailedLogons: false)
    {
    }

    /// <param name="commitFailedLogons">True only for the scheduled snapshot path, whose upload success commits the
    /// failed-logon cursor (<see cref="WindowsTelemetryCollector.MarkSnapshotSubmitted"/>); other callers peek.</param>
    public SecurityTelemetrySectionCollector(bool commitFailedLogons)
        : this(commitFailedLogons, AgentBuildProfile.IsServer, null)
    {
    }

    /// <param name="collectFailedLogons">Only the server profile reads event logs and keeps a cursor file; the desktop
    /// payload has no <c>failed_logons</c> field.</param>
    internal SecurityTelemetrySectionCollector(bool commitFailedLogons, bool collectFailedLogons, FailedLogonCursorStore? cursor)
    {
        _commitFailedLogons = commitFailedLogons;
        _cursor = collectFailedLogons ? cursor ?? new FailedLogonCursorStore() : null;
    }

    public async ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var (domainJoined, domainName, adError) = ProbeAd();
        var section = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["status"] = "ok",
            ["defender"] = TelemetryValue.ReadService("WinDefend"),
            ["bitlocker"] = TelemetryValue.ReadService("BDESVC"),
            ["windows_update"] = TelemetryValue.ReadService("wuauserv"),
            ["ad"] = new
            {
                domain_joined = domainJoined,
                domain_name = domainName,
                error = Sanitizer.Redact(adError),
            },
        };
        if (_cursor is not null)
            section["failed_logons"] = await CollectFailedLogonsAsync(_cursor, ct).ConfigureAwait(false);
        return section;
    }

    private static (bool DomainJoined, string? DomainName, string? Error) ProbeAd()
    {
        try
        {
            return AdStatusProbe.Probe();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            TelemetrySectionCapture.Log?.Warn(
                $"Telemetry section security ad probe {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)} at={ExceptionSite.FirstFrame(ex)}");
            return (false, null, $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private async Task<object> CollectFailedLogonsAsync(FailedLogonCursorStore cursor, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        try
        {
            return await Task.Run(() => FailedLogonSection.Collect(cursor, now, _commitFailedLogons, ct), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            TelemetrySectionCapture.Log?.Warn(
                $"Telemetry section security failed_logons {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)} at={ExceptionSite.FirstFrame(ex)}");
            return FailedLogonSection.Unavailable(now);
        }
    }
}
