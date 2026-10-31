using System.Buffers.Binary;
using System.Globalization;
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
    // The server build only installs; staging for local consent belongs to the desktop build.
    private static readonly HashSet<string> SupportedModes = new(StringComparer.Ordinal)
    {
#if CERBERUS_SERVER_PROFILE
        InstallMode,
#else
        "check",
        "stage",
        "stage_and_prompt",
#endif
    };
    private const string InstallMode = "install";
    internal const string InvalidNotBefore = "not_before_utc must be an ISO-8601 time with an offset, at most 24 hours ahead.";

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
            if (AgentBuildProfile.IsServer)
                return await RejectAsync(ex is InvalidOperationException ? ex.Message : "Update request payload is invalid.")
                    .ConfigureAwait(false);
            var preserved = await AgentUpdateLocalService.ProjectPreservedAttemptAsync(CancellationToken.None)
                .ConfigureAwait(false);
            if (preserved is not null)
                return Failed(ex.Message, preserved);

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
        if (string.Equals(request.Mode, InstallMode, StringComparison.Ordinal))
            return await RequestInstallAsync(request, command, campaignId, ct).ConfigureAwait(false);
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

            var check = await coordinator.CheckUpdateAsync(signal, ct, explicitRequest: true).ConfigureAwait(false);
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
                    manifestUrl: signal.ManifestUrl,
                    campaignId: campaignId,
                    commandId: commandId,
                    markChecked: true).ConfigureAwait(false);
                return Done(available);
            }

            var plan = await coordinator.StageUpdateAsync(
                signal,
                campaignId,
                commandId,
                ct,
                explicitRequest: true).ConfigureAwait(false);
            if (plan is null)
            {
                var current = await _stateStore.WriteTransitionAsync(
                    AgentUpdateStates.Current,
                    _currentVersion,
                    ct,
                    targetVersion: check.Version ?? request.TargetVersion,
                    channel: check.Channel ?? signal.Channel,
                    manifestUrl: signal.ManifestUrl,
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
        catch (AgentUpdateReconciliationDeferredException ex)
        {
            // The service already committed the preserved attempt. Keep the
            // command's FAILED contract while returning journal-derived state.
            var projected = await AgentUpdateLocalService.ProjectCurrentStateAsync(CancellationToken.None)
                .ConfigureAwait(false);
            return Failed(ex.Message, projected);
        }
        catch (OperationCanceledException ex)
        {
            // Cancellation must not overwrite a still-authoritative attempt
            // with a synthetic Failed projection.
            var preserved = await AgentUpdateLocalService.ProjectPreservedAttemptAsync(CancellationToken.None)
                .ConfigureAwait(false);
            if (preserved is not null)
                return Failed(ex.Message, preserved);
            throw;
        }
        catch (Exception ex)
        {
            _log.Warn($"Agent update request failed: {ex.GetType().Name}: {ex.Message}");
            var preserved = await AgentUpdateLocalService.ProjectPreservedAttemptAsync(CancellationToken.None)
                .ConfigureAwait(false);
            if (preserved is not null)
                return Failed(ex.Message, preserved);

            var failed = await _stateStore.WriteTransitionAsync(
                AgentUpdateStates.Failed,
                _currentVersion,
                CancellationToken.None,
                targetVersion: request.TargetVersion,
                channel: AgentUpdateTrustFactory.BuildConfiguredManualSignal()?.Channel,
                manifestUrl: AgentUpdateTrustFactory.BuildConfiguredManualSignal()?.ManifestUrl,
                campaignId: campaignId,
                commandId: commandId,
                errorCode: AgentUpdateErrorCodes.Classify(ex),
                errorMessage: Sanitizer.Redact(ex.Message)).ConfigureAwait(false);
            return Failed(ex.Message, failed);
        }
    }

    /// <summary>
    /// Records the install for the update scheduler and returns at once. The outcome is reported by the update status
    /// and agent version of later heartbeats. A rejection writes nothing.
    /// </summary>
    private async Task<CommandResult> RequestInstallAsync(
        AgentUpdateRequestPayload request,
        AgentCommand command,
        string campaignId,
        CancellationToken ct)
    {
        try
        {
            var notBefore = InstallNotBefore(request.NotBeforeUtc, request.JitterSeconds,
                $"{campaignId}:{command.IdempotencyKey}:{command.Id}", DateTimeOffset.UtcNow);
            if (notBefore is null)
                return await RejectAsync(InvalidNotBefore).ConfigureAwait(false);
            if (_coordinatorFactory() is null)
                return await RejectAsync("Update trust is not configured.").ConfigureAwait(false);
            _ = BuildSignal(request); // manifest URL and channel stay pinned to the installed configuration
            if (!await AgentUpdateLocalService.RequestInstallAsync(notBefore.Value, ct).ConfigureAwait(false))
                return await RejectAsync("Automatic updates are not allowed in the current agent state.").ConfigureAwait(false);
            _log.Info($"Install request recorded: command {command.Id}, not before {notBefore.Value:O}.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Warn($"Install request rejected: {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)}");
            return await RejectAsync(ex is InvalidOperationException ? ex.Message : "Install request could not be recorded.")
                .ConfigureAwait(false);
        }

        try
        {
            return Done(await AgentUpdateLocalService.ProjectCurrentStateAsync(CancellationToken.None).ConfigureAwait(false));
        }
        catch (Exception)
        {
            return Done(await _stateStore.ReadAsync(_currentVersion, CancellationToken.None).ConfigureAwait(false));
        }
    }

    /// <summary>FAILED with the stored state; nothing is written, so the reported update status stays as it was.</summary>
    private async Task<CommandResult> RejectAsync(string message)
        => Failed(message, await _stateStore.ReadAsync(_currentVersion, CancellationToken.None).ConfigureAwait(false));

    /// <summary>
    /// Requested start plus the deterministic jitter, never before now and at most the rollout window ahead. Null when
    /// the requested time has no offset, does not parse, or is more than the rollout window ahead.
    /// </summary>
    internal static DateTimeOffset? InstallNotBefore(string? notBeforeUtc, int? jitterSeconds, string seed, DateTimeOffset now)
    {
        var latest = now.Add(AgentUpdateLocalService.MaxInstallRequestDelay);
        var start = now;
        if (Clean(notBeforeUtc) is { } value)
        {
            if (!HasOffset(value) ||
                !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed) ||
                parsed > latest)
                return null;
            if (parsed > now)
                start = parsed.ToUniversalTime();
        }
        var at = start.Add(DeterministicOffset(TimeSpan.FromSeconds(Math.Clamp(jitterSeconds ?? 0, 0, 3600)), seed));
        return at > latest ? latest : at;
    }

    private static bool HasOffset(string value)
        => value.EndsWith('Z') || value.EndsWith('z') || (value.Length > 6 && value[^6] is '+' or '-' && value[^3] == ':');

    internal static bool SupportsMode(string? mode) => mode is not null && SupportedModes.Contains(mode);

    private static AgentUpdateSignal BuildSignal(AgentUpdateRequestPayload request)
    {
        var configured = AgentUpdateTrustFactory.BuildConfiguredManualSignal()
            ?? throw new InvalidOperationException("Update manifest URL is not configured.");
        var requestedUrl = Clean(request.ManifestUrl);
        if (!string.IsNullOrWhiteSpace(requestedUrl) &&
            !string.Equals(requestedUrl, configured.ManifestUrl, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update manifest URL does not match the installed release configuration.");

        var requestedChannel = Clean(request.Channel);
        if (!string.IsNullOrWhiteSpace(requestedChannel) &&
            !string.Equals(requestedChannel, configured.Channel, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update channel does not match the installed release configuration.");

        return new AgentUpdateSignal(
            Required: false,
            Recommended: true,
            ManifestUrl: configured.ManifestUrl,
            Reason: Clean(request.Reason) ?? "agent_update_request",
            Channel: configured.Channel);
    }

    private static void ValidateRequest(AgentUpdateRequestPayload request)
    {
        if (!string.Equals(request.SchemaVersion, "agent.update.request.v1", StringComparison.Ordinal))
            throw new InvalidOperationException("Unsupported update request schema.");
        if (request.ForceInstall == true)
            throw new InvalidOperationException("force_install is not supported in V1.");
        if (!SupportsMode(request.Mode))
            throw new InvalidOperationException("Unsupported update request mode.");
    }

    private static async Task ApplyJitterAsync(
        AgentUpdateRequestPayload request,
        AgentCommand command,
        string campaignId,
        CancellationToken ct)
    {
        var notBefore = ParseUtc(request.NotBeforeUtc, DateTimeOffset.UtcNow);
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

    private static DateTimeOffset ParseUtc(string? value, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(value))
            return now;
        return DateTimeOffset.TryParse(value, out var parsed)
            ? parsed.ToUniversalTime()
            : now;
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
