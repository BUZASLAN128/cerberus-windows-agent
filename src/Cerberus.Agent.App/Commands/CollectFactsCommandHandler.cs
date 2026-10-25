#if CERBERUS_SERVER_PROFILE
using System.Globalization;
using System.Text.Json;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Commands;

/// <summary>
/// <c>collect_facts</c> (contract v1 (d)), server build only. Collects the requested fact sections
/// (all server sections for <c>{}</c>) with a fresh telemetry context per run, so every run gets its
/// own 20 s / 5 s-per-section budget. The result body is fitted to 262144 bytes with the snapshot's
/// truncation; if it still does not fit the result is FAILED <c>result_too_large</c>.
/// </summary>
internal sealed class CollectFactsCommandHandler : ICommandHandler
{
    public const string Schema = "agent.facts.v1";
    public const string ResultTooLarge = "result_too_large";
    public const int MaxResultBytes = EnvelopeExecutionQueue.MaxResultBodyBytes;

    // The queue measures the final body with the real 64-hex envelope_sha256; the size is the same.
    private static readonly string Sha256Placeholder = new('0', 64);

    private readonly AgentBuildMetadata _metadata;
    private readonly IReadOnlyList<IWindowsTelemetrySectionCollector> _sections;
    private readonly TimeProvider _time;

    public CollectFactsCommandHandler(AgentBuildMetadata metadata)
        : this(metadata, WindowsTelemetrySectionCatalog.CreateDefault(configured: null, publishServiceObservation: false),
            TimeProvider.System)
    {
    }

    internal CollectFactsCommandHandler(
        AgentBuildMetadata metadata,
        IReadOnlyList<IWindowsTelemetrySectionCollector> sections,
        TimeProvider time)
    {
        _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _sections = sections ?? throw new ArgumentNullException(nameof(sections));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public string Type => EnvelopeTypes.CollectFacts;

    public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(command);
        var requested = RequestedSections(command.Payload);
        var context = new WindowsTelemetryContext(_metadata, LastHeartbeat: null);
        var collected = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var section in _sections)
        {
            if (requested is not null && !requested.Contains(section.SectionName))
                continue;
            collected[section.SectionName] = await TelemetrySectionCapture.CaptureAsync(section, context, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
        }

        var collectedAt = _time.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        IReadOnlyDictionary<string, object?> sections = collected;
        var post = Build(collectedAt, sections);
        while (ResultBytes(post) > MaxResultBytes && ServerSnapshotFit.TryHalve(sections, out var smaller))
        {
            sections = smaller;
            post = Build(collectedAt, sections);
        }

        return ResultBytes(post) <= MaxResultBytes
            ? new CommandResult("DONE", 0, null, null, post)
            : new CommandResult("FAILED", null, null, ResultTooLarge, null);
    }

    /// <summary>Null for all sections. The verifier already checked the payload shape (step 12).</summary>
    private static HashSet<string>? RequestedSections(object? payload)
    {
        if (payload is not JsonElement { ValueKind: JsonValueKind.Object } element
            || !element.TryGetProperty("sections", out var list)
            || list.ValueKind != JsonValueKind.Array)
            return null;

        return list.EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString()!)
            .ToHashSet(StringComparer.Ordinal);
    }

    private static Dictionary<string, object?> Build(string collectedAt, IReadOnlyDictionary<string, object?> sections)
        => new(StringComparer.Ordinal)
        {
            ["schema_version"] = Schema,
            ["collected_at"] = collectedAt,
            ["sections"] = sections,
            ["section_hashes"] = sections.ToDictionary(
                pair => pair.Key,
                pair => AgentSnapshotFactory.HashSection(pair.Value),
                StringComparer.Ordinal),
        };

    private static int ResultBytes(object post)
        => CommandEnvelope.BuildResultBody("DONE", 0, null, post, Sha256Placeholder).Length;
}
#endif
