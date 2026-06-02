using System.Text.Json;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Diagnostics;

internal sealed record AgentDiagnosticRequestContext(
    string Source,
    string? RequestedBy,
    string? RequestCommandId,
    string? Reason);

internal sealed class AgentDiagnosticBundleUploader
{
    public const string CommandType = "agent.diagnostic_bundle.collect";
    private readonly AgentApiClient? _api;
    private readonly AgentBuildMetadata _metadata;
    private readonly Func<AgentDiagnosticRequestContext, CancellationToken, Task<AgentDiagnosticBundleAckResponse>>? _upload;

    public AgentDiagnosticBundleUploader(AgentApiClient api, AgentBuildMetadata metadata)
    {
        _api = api;
        _metadata = metadata;
    }

    internal AgentDiagnosticBundleUploader(
        AgentBuildMetadata metadata,
        Func<AgentDiagnosticRequestContext, CancellationToken, Task<AgentDiagnosticBundleAckResponse>> upload)
    {
        _metadata = metadata;
        _upload = upload;
    }

    public async Task<AgentDiagnosticBundleAckResponse> UploadAsync(
        AgentDiagnosticRequestContext context,
        CancellationToken ct)
    {
        if (_upload is not null)
            return await _upload(context, ct).ConfigureAwait(false);
        var request = await BuildRequestAsync(_metadata, context, ct).ConfigureAwait(false);
        return await _api!.SubmitDiagnosticBundleAsync(request, ct).ConfigureAwait(false);
    }

    internal static async Task<AgentDiagnosticBundleRequest> BuildRequestAsync(
        AgentBuildMetadata metadata,
        AgentDiagnosticRequestContext context,
        CancellationToken ct)
    {
        var collectedAt = DateTimeOffset.UtcNow;
        var requestMeta = BuildRequestMetadata(context);
        var payload = await BuildPayloadAsync(metadata, ct).ConfigureAwait(false);
        var summary = BuildSummary(metadata, payload, requestMeta);
        var manifest = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["sections"] = payload.Keys.OrderBy(x => x, StringComparer.Ordinal).ToArray(),
            ["generated_by"] = "cerberus-agent-service",
            ["request"] = requestMeta,
        };
        var bundleId = $"diag-{collectedAt:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..38];
        return AgentTelemetryFactory.CreateDiagnosticBundle(
            metadata,
            clientBundleId: bundleId,
            manifest: manifest,
            summary: summary,
            payload: payload,
            collectedAtUtc: collectedAt);
    }

    private static Dictionary<string, object?> BuildRequestMetadata(AgentDiagnosticRequestContext context)
        => new(StringComparer.Ordinal)
        {
            ["source"] = Clean(context.Source) == "scheduled" ? "scheduled" : "manual",
            ["requested_by"] = Clean(context.RequestedBy),
            ["request_command_id"] = Clean(context.RequestCommandId),
            ["reason"] = Clean(context.Reason),
        };

    private static async Task<Dictionary<string, object?>> BuildPayloadAsync(
        AgentBuildMetadata metadata,
        CancellationToken ct)
    {
        var context = new WindowsTelemetryContext(metadata, LastHeartbeat: null);
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["agent"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["status"] = "ok",
                ["version"] = metadata.AgentVersion,
                ["build_id"] = metadata.BuildId,
                ["build_channel"] = metadata.BuildChannel,
                ["boot_id"] = metadata.BootId,
            },
            ["service"] = BuildServiceSection(),
            ["runtime"] = await CaptureSectionAsync(new RuntimeTelemetrySectionCollector(), context, ct).ConfigureAwait(false),
            ["clock"] = await CaptureSectionAsync(new ClockTelemetrySectionCollector(), context, ct).ConfigureAwait(false),
            ["rdp"] = await CaptureSectionAsync(new RdpTelemetrySectionCollector(), context, ct).ConfigureAwait(false),
            ["firewall"] = await CaptureSectionAsync(new FirewallTelemetrySectionCollector(), context, ct).ConfigureAwait(false),
            ["tailscale"] = await CaptureTailscaleAsync(ct).ConfigureAwait(false),
        };
        payload["api_reachability"] = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["status"] = "last_upload_attempt",
            ["checked_at_utc"] = DateTimeOffset.UtcNow.ToString("O"),
        };
        return payload;
    }

    private static Dictionary<string, object?> BuildSummary(
        AgentBuildMetadata metadata,
        IReadOnlyDictionary<string, object?> payload,
        IReadOnlyDictionary<string, object?> requestMeta)
    {
        var service = payload.TryGetValue("service", out var serviceValue) ? serviceValue : null;
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["overall_status"] = "ok",
            ["service_status"] = ExtractStatus(service) ?? "unknown",
            ["agent_version"] = metadata.AgentVersion,
            ["clock_status"] = ExtractStatus(TryGet(payload, "clock")) ?? "unknown",
            ["api_reachability"] = "last_upload_attempt",
            ["rdp_readiness"] = ExtractStatus(TryGet(payload, "rdp")) ?? "unknown",
            ["firewall_readiness"] = ExtractStatus(TryGet(payload, "firewall")) ?? "unknown",
            ["tailscale_status"] = ExtractStatus(TryGet(payload, "tailscale")) ?? "unknown",
            ["generated_by"] = "cerberus-agent-service",
            ["request"] = requestMeta,
        };
    }

    private static Dictionary<string, object?> BuildServiceSection()
    {
        var service = AgentStatus.GetService();
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["status"] = service.Installed ? service.Short : "not_installed",
            ["state"] = service.Short,
            ["label"] = service.Text,
            ["installed"] = service.Installed,
        };
    }

    private static async Task<object?> CaptureTailscaleAsync(CancellationToken ct)
    {
        var (installed, connected, snapshot, error) = await TailscaleStatusProbe
            .ProbeAsync(TimeSpan.FromSeconds(4), ct)
            .ConfigureAwait(false);
        return new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["status"] = connected ? "connected" : installed ? "installed" : "not_installed",
            ["installed"] = installed,
            ["connected"] = connected,
            ["snapshot"] = snapshot,
            ["error"] = AgentDiagnosticsBundle.Redact(error),
        };
    }

    private static async Task<object?> CaptureSectionAsync(
        IWindowsTelemetrySectionCollector collector,
        WindowsTelemetryContext context,
        CancellationToken ct)
    {
        try
        {
            return await TelemetrySectionCapture.CaptureAsync(collector, context, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["status"] = "error",
                ["error"] = AgentDiagnosticsBundle.Redact(ex.Message),
            };
        }
    }

    private static string? ExtractStatus(object? value)
    {
        if (value is IReadOnlyDictionary<string, object?> map)
        {
            foreach (var key in new[] { "status", "state", "health", "readiness" })
            {
                if (map.TryGetValue(key, out var raw) && raw is not null)
                    return Clean(Convert.ToString(raw));
            }
        }
        var json = JsonSerializer.Serialize(value);
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind == JsonValueKind.Object)
        {
            foreach (var key in new[] { "status", "state", "health", "readiness" })
            {
                if (doc.RootElement.TryGetProperty(key, out var prop) && prop.ValueKind == JsonValueKind.String)
                    return Clean(prop.GetString());
            }
        }
        return null;
    }

    private static object? TryGet(IReadOnlyDictionary<string, object?> payload, string key)
        => payload.TryGetValue(key, out var value) ? value : null;

    private static string? Clean(string? value)
    {
        var clean = AgentDiagnosticsBundle.Redact(value).Trim();
        return string.IsNullOrWhiteSpace(clean) ? null : clean.Length <= 160 ? clean : clean[..160];
    }
}
