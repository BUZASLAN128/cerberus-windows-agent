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
    private readonly SecurityPostureCache _posture;

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
    /// <param name="posture">Background Defender/SMB1 cache; the collector only reads its last result.</param>
    internal SecurityTelemetrySectionCollector(bool commitFailedLogons, bool collectFailedLogons, FailedLogonCursorStore? cursor, SecurityPostureCache? posture = null)
    {
        _posture = posture ?? SecurityPostureCache.Shared;
        _commitFailedLogons = commitFailedLogons;
        _cursor = collectFailedLogons ? cursor ?? new FailedLogonCursorStore() : null;
        if (collectFailedLogons)
            _posture.Warm();
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
        {
            // One Security scan feeds failed_logons, successful_logons, log_cleared and local_admins.changes.
            var log = await CollectSecurityLogAsync(_cursor, ct).ConfigureAwait(false);
            section["failed_logons"] = log.FailedLogons;
            section["successful_logons"] = log.SuccessfulLogons;
            section["log_cleared"] = log.LogCleared;
            section["local_admins"] = await CollectLocalAdminsAsync(log.AdminChanges, ct).ConfigureAwait(false);
            section["unexpected_shutdowns"] = await CollectUnexpectedShutdownsAsync(ct).ConfigureAwait(false);
            foreach (var (key, value) in _posture.Current())
                section[key] = value;
        }
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

    private async Task<SecurityLogResult> CollectSecurityLogAsync(FailedLogonCursorStore cursor, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        try
        {
            return await Task.Run(() => FailedLogonSection.CollectAll(cursor, now, _commitFailedLogons, ct), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            WarnProbe("failed_logons", ex);
            return SecurityLogResult.Unavailable(now);
        }
    }

    private static async Task<object> CollectLocalAdminsAsync(AdminChangeReport changes, CancellationToken ct)
    {
        LocalAdminsRead? members = null;
        try
        {
            members = await Task.Run(() => LocalAdminsProbe.Read(ct), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            WarnProbe("local_admins", ex);
        }
        return SecurityLogFields.LocalAdmins(members, changes);
    }

    private static async Task<object> CollectUnexpectedShutdownsAsync(CancellationToken ct)
    {
        try
        {
            var read = await Task.Run(() => UnexpectedShutdownsProbe.Read(ct), ct).ConfigureAwait(false);
            return new
            {
                status = "ok",
                count_7d = read.Count7d,
                last_utc = read.LastUtc is { } t ? FailedLogonSection.Iso(t) : null,
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            WarnProbe("unexpected_shutdowns", ex);
            return SecurityLogFields.Unavailable;
        }
    }

    private static void WarnProbe(string field, Exception ex)
        => TelemetrySectionCapture.Log?.Warn(
            $"Telemetry section security {field} {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)} at={ExceptionSite.FirstFrame(ex)}");
}
