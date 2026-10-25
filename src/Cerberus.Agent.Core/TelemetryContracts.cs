using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
#if CERBERUS_SERVER_PROFILE
    public const int MaxSnapshotBytes = 262144;
#else
    public const int MaxSnapshotBytes = MaxJsonBytes;
#endif

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

#if CERBERUS_SERVER_PROFILE
    // The server fact sections come from the one list collect_facts validates against.
    static AgentSnapshotFactory() => AllowedSections.UnionWith(EnvelopeTypes.ServerFactSections);
#endif

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

        var request = Build(metadata, collectedAtUtc, sections);
#if CERBERUS_SERVER_PROFILE
        while (AgentTelemetryLimits.EstimateJsonBytes(request) > AgentTelemetryLimits.MaxSnapshotBytes
               && ServerSnapshotFit.TryHalve(sections, out var smaller))
        {
            sections = smaller;
            request = Build(metadata, collectedAtUtc, sections);
        }
#endif

        AgentTelemetryLimits.ThrowIfTooLarge(request, AgentTelemetryLimits.MaxSnapshotBytes);
        return request;
    }

    private static AgentSnapshotRequest Build(
        AgentBuildMetadata metadata,
        DateTimeOffset collectedAtUtc,
        IReadOnlyDictionary<string, object?> sections)
    {
        var hashes = sections.ToDictionary(
            pair => pair.Key,
            pair => HashSection(pair.Value),
            StringComparer.Ordinal);

        return new AgentSnapshotRequest(
            SchemaVersion: AgentSchemaVersions.Snapshot,
            AgentVersion: metadata.AgentVersion,
            BuildId: metadata.BuildId,
            BuildChannel: metadata.BuildChannel,
            SupportedSchemaVersions: metadata.SupportedSchemaVersions,
            CollectedAt: collectedAtUtc.ToString("O"),
            SectionHashes: hashes,
            Sections: sections);
    }

    /// <summary>
    /// Copy of <paramref name="request"/> without one field of one section (hash of that section recomputed); the
    /// request itself when the field is absent. Used so a buffered snapshot never carries consume-once data
    /// (<c>security.failed_logons</c>) that the next live snapshot re-reads and reports.
    /// </summary>
    public static AgentSnapshotRequest WithoutSectionField(AgentSnapshotRequest request, string section, string field)
    {
        if (!request.Sections.TryGetValue(section, out var value) || value is null
            || JsonSerializer.SerializeToNode(value, JsonOpts) is not JsonObject node
            || !node.Remove(field))
            return request;

        var sections = new Dictionary<string, object?>(request.Sections, StringComparer.Ordinal) { [section] = node };
        var hashes = new Dictionary<string, string>(request.SectionHashes, StringComparer.Ordinal) { [section] = HashSection(node) };
        return request with { Sections = sections, SectionHashes = hashes };
    }

    public static string HashSection(object? section)
    {
        var json = JsonSerializer.Serialize(section, JsonOpts);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

#if CERBERUS_SERVER_PROFILE
/// <summary>
/// Server-profile snapshot fitting (contract section e): when the body is over the cap, the largest list is
/// halved, in the order software, services, listening_ports, and the section's <c>truncated</c> is set.
/// </summary>
public static class ServerSnapshotFit
{
    private static readonly (string Section, string List)[] Order =
    {
        ("software", "software"),
        ("services", "services"),
        ("listening_ports", "ports"),
    };

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public static bool TryHalve(IReadOnlyDictionary<string, object?> sections, out IReadOnlyDictionary<string, object?> smaller)
    {
        foreach (var (section, list) in Order)
        {
            if (!sections.TryGetValue(section, out var value) || value is null)
                continue;
            if (JsonSerializer.SerializeToNode(value, JsonOpts) is not JsonObject node
                || node[list] is not JsonArray items
                || items.Count == 0)
                continue;

            var keep = items.Count / 2;
            var halved = new JsonArray();
            for (var i = 0; i < keep; i++)
                halved.Add(items[i]!.DeepClone());
            node[list] = halved;
            node["truncated"] = true;

            var copy = new Dictionary<string, object?>(sections, StringComparer.Ordinal) { [section] = node };
            smaller = copy;
            return true;
        }

        smaller = sections;
        return false;
    }
}
#endif

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
