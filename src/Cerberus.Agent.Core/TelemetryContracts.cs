using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public static class AgentSchemaVersions
{
    public const string Heartbeat = "agent.heartbeat.v1";
    public const string Snapshot = "agent.snapshot.v1";
    public const string Events = "agent.events.v1";
    public const string ProbeResult = "agent.probe-result.v1";
    public const string DiagnosticBundle = "agent.diagnostic_bundle.v1";

    public static readonly IReadOnlyList<string> All = new[]
    {
        Heartbeat,
        Snapshot,
        Events,
        ProbeResult,
        DiagnosticBundle,
    };
}

public static class AgentTelemetryLimits
{
    public const int MaxJsonBytes = 64 * 1024;
    public const int MaxDiagnosticBundleBytes = 256 * 1024;

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public static int EstimateJsonBytes(object body)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        return Encoding.UTF8.GetByteCount(json);
    }

    public static void ThrowIfTooLarge(object body, int maxBytes = MaxJsonBytes)
    {
        var bytes = EstimateJsonBytes(body);
        if (bytes > maxBytes)
            throw new InvalidOperationException($"Agent telemetry payload too large: {bytes} bytes.");
    }
}

public sealed record AgentBuildMetadata(
    string AgentVersion,
    string BuildId,
    string BuildChannel,
    string BootId,
    IReadOnlyList<string> SupportedSchemaVersions);

public sealed record AgentSnapshotRequest(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("agent_version")] string AgentVersion,
    [property: JsonPropertyName("build_id")] string BuildId,
    [property: JsonPropertyName("build_channel")] string BuildChannel,
    [property: JsonPropertyName("supported_schema_versions")] IReadOnlyList<string> SupportedSchemaVersions,
    [property: JsonPropertyName("collected_at")] string CollectedAt,
    [property: JsonPropertyName("section_hashes")] IReadOnlyDictionary<string, string> SectionHashes,
    [property: JsonPropertyName("sections")] IReadOnlyDictionary<string, object?> Sections);

public sealed record AgentEventItem(
    [property: JsonPropertyName("event_id")] string EventId,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("occurred_at")] string OccurredAt,
    [property: JsonPropertyName("severity")] string Severity,
    [property: JsonPropertyName("payload")] IReadOnlyDictionary<string, object?> Payload);

public sealed record AgentEventBatchRequest(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("agent_version")] string AgentVersion,
    [property: JsonPropertyName("build_id")] string BuildId,
    [property: JsonPropertyName("build_channel")] string BuildChannel,
    [property: JsonPropertyName("supported_schema_versions")] IReadOnlyList<string> SupportedSchemaVersions,
    [property: JsonPropertyName("events")] IReadOnlyList<AgentEventItem> Events);

public sealed record AgentProbeResultRequest(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("agent_version")] string AgentVersion,
    [property: JsonPropertyName("build_id")] string BuildId,
    [property: JsonPropertyName("build_channel")] string BuildChannel,
    [property: JsonPropertyName("supported_schema_versions")] IReadOnlyList<string> SupportedSchemaVersions,
    [property: JsonPropertyName("result_id")] string ResultId,
    [property: JsonPropertyName("probe_id")] string ProbeId,
    [property: JsonPropertyName("collected_at")] string CollectedAt,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("command_id")] string? CommandId,
    [property: JsonPropertyName("payload")] IReadOnlyDictionary<string, object?> Payload);

public sealed record AgentDiagnosticBundleRequest(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("agent_version")] string AgentVersion,
    [property: JsonPropertyName("build_id")] string BuildId,
    [property: JsonPropertyName("build_channel")] string BuildChannel,
    [property: JsonPropertyName("supported_schema_versions")] IReadOnlyList<string> SupportedSchemaVersions,
    [property: JsonPropertyName("client_bundle_id")] string ClientBundleId,
    [property: JsonPropertyName("collected_at")] string CollectedAt,
    [property: JsonPropertyName("manifest")] IReadOnlyDictionary<string, object?> Manifest,
    [property: JsonPropertyName("summary")] IReadOnlyDictionary<string, object?> Summary,
    [property: JsonPropertyName("payload")] IReadOnlyDictionary<string, object?> Payload);

public sealed record AgentIngestAckResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("accepted")] int Accepted,
    [property: JsonPropertyName("ignored")] int Ignored,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("changed_sections")] IReadOnlyList<string>? ChangedSections);

public sealed record AgentDiagnosticBundleAckResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("bundle_id")] string BundleId,
    [property: JsonPropertyName("accepted")] int Accepted,
    [property: JsonPropertyName("ignored")] int Ignored,
    [property: JsonPropertyName("reason")] string? Reason);

public static class AgentSnapshotFactory
{
    private static readonly HashSet<string> AllowedSections = new(StringComparer.Ordinal)
    {
        "identity",
        "os",
        "resources",
        "network",
        "tailscale",
        "rdp",
        "firewall",
        "security",
        "clock",
        "runtime",
        "capabilities",
    };

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public static AgentSnapshotRequest Create(
        AgentBuildMetadata metadata,
        DateTimeOffset collectedAtUtc,
        IReadOnlyDictionary<string, object?> sections)
    {
        foreach (var section in sections.Keys)
        {
            if (!AllowedSections.Contains(section))
                throw new InvalidOperationException($"Unknown agent snapshot section: {section}");
        }

        var hashes = sections.ToDictionary(
            pair => pair.Key,
            pair => HashSection(pair.Value),
            StringComparer.Ordinal);

        var request = new AgentSnapshotRequest(
            SchemaVersion: AgentSchemaVersions.Snapshot,
            AgentVersion: metadata.AgentVersion,
            BuildId: metadata.BuildId,
            BuildChannel: metadata.BuildChannel,
            SupportedSchemaVersions: metadata.SupportedSchemaVersions,
            CollectedAt: collectedAtUtc.ToString("O"),
            SectionHashes: hashes,
            Sections: sections);

        AgentTelemetryLimits.ThrowIfTooLarge(request);
        return request;
    }

    public static string HashSection(object? section)
    {
        var json = JsonSerializer.Serialize(section, JsonOpts);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

public static class AgentTelemetryFactory
{
    public static AgentEventBatchRequest CreateEvents(
        AgentBuildMetadata metadata,
        IReadOnlyList<AgentEventItem> events)
    {
        var request = new AgentEventBatchRequest(
            SchemaVersion: AgentSchemaVersions.Events,
            AgentVersion: metadata.AgentVersion,
            BuildId: metadata.BuildId,
            BuildChannel: metadata.BuildChannel,
            SupportedSchemaVersions: metadata.SupportedSchemaVersions,
            Events: events);
        AgentTelemetryLimits.ThrowIfTooLarge(request);
        return request;
    }

    public static AgentProbeResultRequest CreateProbeResult(
        AgentBuildMetadata metadata,
        string resultId,
        string probeId,
        string status,
        IReadOnlyDictionary<string, object?> payload,
        string? commandId = null,
        DateTimeOffset? collectedAtUtc = null)
    {
        var request = new AgentProbeResultRequest(
            SchemaVersion: AgentSchemaVersions.ProbeResult,
            AgentVersion: metadata.AgentVersion,
            BuildId: metadata.BuildId,
            BuildChannel: metadata.BuildChannel,
            SupportedSchemaVersions: metadata.SupportedSchemaVersions,
            ResultId: resultId,
            ProbeId: probeId,
            CollectedAt: (collectedAtUtc ?? DateTimeOffset.UtcNow).ToString("O"),
            Status: status,
            CommandId: commandId,
            Payload: payload);
        AgentTelemetryLimits.ThrowIfTooLarge(request);
        return request;
    }

    public static AgentDiagnosticBundleRequest CreateDiagnosticBundle(
        AgentBuildMetadata metadata,
        string clientBundleId,
        IReadOnlyDictionary<string, object?> manifest,
        IReadOnlyDictionary<string, object?> summary,
        IReadOnlyDictionary<string, object?> payload,
        DateTimeOffset? collectedAtUtc = null)
    {
        var request = new AgentDiagnosticBundleRequest(
            SchemaVersion: AgentSchemaVersions.DiagnosticBundle,
            AgentVersion: metadata.AgentVersion,
            BuildId: metadata.BuildId,
            BuildChannel: metadata.BuildChannel,
            SupportedSchemaVersions: metadata.SupportedSchemaVersions,
            ClientBundleId: clientBundleId,
            CollectedAt: (collectedAtUtc ?? DateTimeOffset.UtcNow).ToString("O"),
            Manifest: manifest,
            Summary: summary,
            Payload: payload);
        AgentTelemetryLimits.ThrowIfTooLarge(request, AgentTelemetryLimits.MaxDiagnosticBundleBytes);
        return request;
    }
}
