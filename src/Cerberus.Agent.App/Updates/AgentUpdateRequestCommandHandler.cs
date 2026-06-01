using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

internal sealed class AgentUpdateRequestCommandHandler : ICommandHandler
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly HashSet<string> SupportedModes = new(StringComparer.Ordinal)
    {
        "check",
        "stage",
        "stage_and_prompt",
    };

    private readonly Func<AgentUpdateCoordinator?> _coordinatorFactory;
    private readonly AgentUpdateStateStore _stateStore;
    private readonly IAgentLogger _log;
    private readonly string _currentVersion;

    public AgentUpdateRequestCommandHandler(
        Func<AgentUpdateCoordinator?> coordinatorFactory,
        AgentUpdateStateStore stateStore,
        IAgentLogger log,
        string currentVersion)
    {
        _coordinatorFactory = coordinatorFactory;
        _stateStore = stateStore;
        _log = log;
        _currentVersion = currentVersion;
    }

    public string Type => "agent.update.request";

    public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
    {
        AgentUpdateRequestPayload request;
        try
        {
            request = ParsePayload(command.Payload);
            ValidateRequest(request);
        }
        catch (Exception ex)
        {
            var failed = await _stateStore.WriteTransitionAsync(
                AgentUpdateStates.Failed,
                _currentVersion,
                ct,
                errorCode: AgentUpdateErrorCodes.Unknown,
                errorMessage: ex.Message).ConfigureAwait(false);
            return Failed(ex.Message, failed);
        }

        var campaignId = Clean(request.CampaignId) ?? command.Id;
        var commandId = command.Id;
        try
        {
            await ApplyJitterAsync(request, command, campaignId, ct).ConfigureAwait(false);

            var coordinator = _coordinatorFactory();
            if (coordinator is null)
            {
                var failed = await _stateStore.WriteTransitionAsync(
                    AgentUpdateStates.Failed,
                    _currentVersion,
                    ct,
                    targetVersion: request.TargetVersion,
                    channel: request.Channel,
                    manifestUrl: request.ManifestUrl,
                    campaignId: campaignId,
                    commandId: commandId,
                    errorCode: AgentUpdateErrorCodes.NotConfigured,
                    errorMessage: "Update trust is not configured.").ConfigureAwait(false);
                return Failed("Update trust is not configured.", failed);
            }

            var signal = BuildSignal(request);
            await _stateStore.WriteTransitionAsync(
                AgentUpdateStates.Checking,
                _currentVersion,
                ct,
                targetVersion: request.TargetVersion,
                channel: signal.Channel,
                manifestUrl: signal.ManifestUrl,
                campaignId: campaignId,
                commandId: commandId).ConfigureAwait(false);

            var check = await coordinator.CheckUpdateAsync(signal, ct).ConfigureAwait(false);
            if (!check.Available)
            {
                var current = await _stateStore.WriteTransitionAsync(
                    AgentUpdateStates.Current,
                    _currentVersion,
                    ct,
                    targetVersion: request.TargetVersion,
                    channel: signal.Channel,
                    manifestUrl: signal.ManifestUrl,
                    campaignId: campaignId,
                    commandId: commandId,
                    markChecked: true).ConfigureAwait(false);
                return Done(current);
            }

            if (string.Equals(request.Mode, "check", StringComparison.Ordinal))
            {
                var available = await _stateStore.WriteTransitionAsync(
                    AgentUpdateStates.Available,
                    _currentVersion,
                    ct,
                    targetVersion: check.Version ?? request.TargetVersion,
                    channel: check.Channel ?? signal.Channel,
                    manifestUrl: check.ManifestUrl ?? signal.ManifestUrl,
                    campaignId: campaignId,
                    commandId: commandId,
                    markChecked: true).ConfigureAwait(false);
                return Done(available);
            }

            var plan = await coordinator.StageUpdateAsync(signal, campaignId, commandId, ct).ConfigureAwait(false);
            if (plan is null)
            {
                var current = await _stateStore.WriteTransitionAsync(
                    AgentUpdateStates.Current,
                    _currentVersion,
                    ct,
                    targetVersion: check.Version ?? request.TargetVersion,
                    channel: check.Channel ?? signal.Channel,
                    manifestUrl: check.ManifestUrl ?? signal.ManifestUrl,
                    campaignId: campaignId,
                    commandId: commandId,
                    markChecked: true).ConfigureAwait(false);
                return Done(current);
            }

            var state = string.Equals(request.Mode, "stage_and_prompt", StringComparison.Ordinal)
                ? AgentUpdateStates.Prompting
                : AgentUpdateStates.Staged;
            var staged = await _stateStore.WriteTransitionAsync(
                state,
                _currentVersion,
                ct,
                targetVersion: plan.Version,
                channel: plan.Channel,
                manifestUrl: signal.ManifestUrl,
                campaignId: campaignId,
                commandId: commandId,
                artifactSha256: plan.Sha256).ConfigureAwait(false);
            return Done(staged);
        }
        catch (Exception ex)
        {
            _log.Warn($"Agent update request failed: {ex.GetType().Name}: {ex.Message}");
            var failed = await _stateStore.WriteTransitionAsync(
                AgentUpdateStates.Failed,
                _currentVersion,
                CancellationToken.None,
                targetVersion: request.TargetVersion,
                channel: request.Channel,
                manifestUrl: request.ManifestUrl,
                campaignId: campaignId,
                commandId: commandId,
                errorCode: AgentUpdateErrorCodes.Classify(ex),
                errorMessage: Sanitizer.Redact(ex.Message)).ConfigureAwait(false);
            return Failed(ex.Message, failed);
        }
    }

    private static AgentUpdateSignal BuildSignal(AgentUpdateRequestPayload request)
    {
        var configured = AgentUpdateTrustFactory.BuildConfiguredManualSignal();
        var manifestUrl = Clean(request.ManifestUrl) ?? configured?.ManifestUrl;
        if (string.IsNullOrWhiteSpace(manifestUrl))
            throw new InvalidOperationException("Update manifest URL is required.");
        return new AgentUpdateSignal(
            Required: false,
            Recommended: true,
            ManifestUrl: manifestUrl,
            Reason: Clean(request.Reason) ?? "agent_update_request",
            Channel: Clean(request.Channel) ?? configured?.Channel ?? WindowsDeviceInfo.GetBuildChannel());
    }

    private static void ValidateRequest(AgentUpdateRequestPayload request)
    {
        if (!string.Equals(request.SchemaVersion, "agent.update.request.v1", StringComparison.Ordinal))
            throw new InvalidOperationException("Unsupported update request schema.");
        if (request.ForceInstall == true)
            throw new InvalidOperationException("force_install is not supported in V1.");
        if (string.IsNullOrWhiteSpace(request.Mode) || !SupportedModes.Contains(request.Mode))
            throw new InvalidOperationException("Unsupported update request mode.");
    }

    private static async Task ApplyJitterAsync(
        AgentUpdateRequestPayload request,
        AgentCommand command,
        string campaignId,
        CancellationToken ct)
    {
        var notBefore = ParseUtc(request.NotBeforeUtc);
        var jitter = TimeSpan.FromSeconds(Math.Clamp(request.JitterSeconds ?? 0, 0, 3600));
        if (jitter > TimeSpan.Zero)
            notBefore = notBefore.Add(DeterministicOffset(jitter, $"{campaignId}:{command.IdempotencyKey}:{command.Id}"));

        var delay = notBefore - DateTimeOffset.UtcNow;
        if (delay > TimeSpan.Zero)
            await Task.Delay(delay, ct).ConfigureAwait(false);
    }

    private static TimeSpan DeterministicOffset(TimeSpan max, string seed)
    {
        var seconds = (int)Math.Max(0, Math.Floor(max.TotalSeconds));
        if (seconds == 0)
            return TimeSpan.Zero;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var value = BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(0, 4));
        return TimeSpan.FromSeconds(value % (uint)(seconds + 1));
    }

    private static DateTimeOffset ParseUtc(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return DateTimeOffset.UtcNow;
        return DateTimeOffset.TryParse(value, out var parsed)
            ? parsed.ToUniversalTime()
            : DateTimeOffset.UtcNow;
    }

    private static AgentUpdateRequestPayload ParsePayload(object payload)
    {
        if (payload is JsonElement element)
        {
            var parsed = element.Deserialize<AgentUpdateRequestPayload>(JsonOptions);
            return parsed ?? throw new InvalidOperationException("Update request payload is empty.");
        }

        var raw = JsonSerializer.Serialize(payload, JsonOptions);
        return JsonSerializer.Deserialize<AgentUpdateRequestPayload>(raw, JsonOptions)
               ?? throw new InvalidOperationException("Update request payload is empty.");
    }

    private static CommandResult Done(AgentUpdateState state)
        => new("DONE", 0, null, null, state.ToCommandResultPayload());

    private static CommandResult Failed(string message, AgentUpdateState state)
        => new("FAILED", 1, null, Sanitizer.Redact(message), state.ToCommandResultPayload());

    private static string? Clean(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private sealed record AgentUpdateRequestPayload(
        [property: JsonPropertyName("schema_version")] string? SchemaVersion,
        [property: JsonPropertyName("campaign_id")] string? CampaignId,
        [property: JsonPropertyName("mode")] string? Mode,
        [property: JsonPropertyName("target_version")] string? TargetVersion,
        [property: JsonPropertyName("channel")] string? Channel,
        [property: JsonPropertyName("manifest_url")] string? ManifestUrl,
        [property: JsonPropertyName("reason")] string? Reason,
        [property: JsonPropertyName("not_before_utc")] string? NotBeforeUtc,
        [property: JsonPropertyName("jitter_seconds")] int? JitterSeconds,
        [property: JsonPropertyName("force_install")] bool? ForceInstall);
}
