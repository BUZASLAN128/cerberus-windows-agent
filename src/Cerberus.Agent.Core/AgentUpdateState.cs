using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

public static class AgentUpdateStates
{
    public const string NotChecked = "not_checked";
    public const string Checking = "checking";
    public const string Current = "current";
    public const string Available = "available";
    public const string Downloading = "downloading";
    public const string Staged = "staged";
    public const string Prompting = "prompting";
    public const string Applying = "applying";
    public const string InstallerStarted = "installer_started";
    public const string Applied = "applied";
    public const string Failed = "failed";
    public const string AwaitingConsent = "awaiting_consent";
    public const string Installing = "installing";
    public const string HealthPending = "health_pending";
    public const string PendingReboot = "pending_reboot";
    public const string Installed = "installed";
    public const string RetryableBusy = "retryable_busy";
    public const string RecoveryRequired = "recovery_required";
    public const string Quarantined = "quarantined";
    public const string Blocked = "blocked";

    public static bool CanApply(string? state)
        => string.Equals(state, Available, StringComparison.Ordinal) ||
           string.Equals(state, Staged, StringComparison.Ordinal) ||
           string.Equals(state, Prompting, StringComparison.Ordinal) ||
           string.Equals(state, AwaitingConsent, StringComparison.Ordinal);
}

public static class AgentUpdateErrorCodes
{
    public const string NotConfigured = "not_configured";
    public const string ManifestUnavailable = "manifest_unavailable";
    public const string ManifestInvalid = "manifest_invalid";
    public const string SignatureInvalid = "signature_invalid";
    public const string ChannelMismatch = "channel_mismatch";
    public const string ArtifactUrlDenied = "artifact_url_denied";
    public const string ArtifactTooLarge = "artifact_too_large";
    public const string DownloadFailed = "download_failed";
    public const string HashMismatch = "hash_mismatch";
    public const string StagingFailed = "staging_failed";
    public const string UacCancelled = "uac_cancelled";
    public const string InstallerBusy = "installer_busy";
    public const string RebootRequired = "reboot_required";
    public const string MsiFailed = "msi_failed";
    public const string RecoveryTimeout = "recovery_timeout";
    public const string Unknown = "unknown";

    public static string Classify(Exception ex)
    {
        if (ex is OperationCanceledException)
            return DownloadFailed;
        if (ex is InvalidOperationException invalid &&
            invalid.Message.Contains("canceled", StringComparison.OrdinalIgnoreCase))
            return UacCancelled;
        if (ex.Message.Contains("signature", StringComparison.OrdinalIgnoreCase))
            return SignatureInvalid;
        if (ex.Message.Contains("channel", StringComparison.OrdinalIgnoreCase))
            return ChannelMismatch;
        if (ex.Message.Contains("hash", StringComparison.OrdinalIgnoreCase) ||
            ex.Message.Contains("sha256", StringComparison.OrdinalIgnoreCase))
            return HashMismatch;
        if (ex.Message.Contains("artifact URL", StringComparison.OrdinalIgnoreCase))
            return ArtifactUrlDenied;
        if (ex.Message.Contains("download failed", StringComparison.OrdinalIgnoreCase))
            return DownloadFailed;
        if (ex.Message.Contains("unavailable", StringComparison.OrdinalIgnoreCase))
            return ManifestUnavailable;
        if (ex.Message.Contains("manifest", StringComparison.OrdinalIgnoreCase))
            return ManifestInvalid;
        return Unknown;
    }
}

public sealed record AgentUpdateState(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("current_version")] string? CurrentVersion,
    [property: JsonPropertyName("target_version")] string? TargetVersion,
    [property: JsonPropertyName("channel")] string? Channel,
    [property: JsonPropertyName("manifest_url")] string? ManifestUrl,
    [property: JsonPropertyName("campaign_id")] string? CampaignId,
    [property: JsonPropertyName("command_id")] string? CommandId,
    [property: JsonPropertyName("artifact_sha256")] string? ArtifactSha256,
    [property: JsonPropertyName("last_checked_utc")] string? LastCheckedUtc,
    [property: JsonPropertyName("last_transition_utc")] string LastTransitionUtc,
    [property: JsonPropertyName("last_error_code")] string? LastErrorCode,
    [property: JsonPropertyName("last_error_message")] string? LastErrorMessage,
    [property: JsonPropertyName("msi_exit_code")] int? MsiExitCode,
    [property: JsonPropertyName("requires_reboot")] bool RequiresReboot,
    [property: JsonPropertyName("last_installer_result_id")] string? LastInstallerResultId,
    [property: JsonPropertyName("attempt_id")] string? AttemptId = null,
    [property: JsonPropertyName("sequence")] long Sequence = 0,
    [property: JsonPropertyName("retry_count")] int RetryCount = 0,
    [property: JsonPropertyName("retry_after_utc")] string? RetryAfterUtc = null,
    [property: JsonPropertyName("quarantined")] bool Quarantined = false,
    [property: JsonPropertyName("release_id")] string? ReleaseId = null,
    [property: JsonPropertyName("report_sequence")] long ReportSequence = 0,
    [property: JsonPropertyName("policy")] string Policy = "recommended",
    [property: JsonPropertyName("health_state")] string HealthState = "unknown",
    [property: JsonPropertyName("rollback_state")] string RollbackState = "none")
{
    public const string CurrentSchemaVersion = "agent.update.state.v1";

    public static AgentUpdateState NotChecked(string? currentVersion = null)
        => new(
            CurrentSchemaVersion,
            AgentUpdateStates.NotChecked,
            NullIfBlank(currentVersion),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            Now(),
            null,
            null,
            null,
            false,
            null);

    public AgentUpdateState Transition(
        string state,
        string? currentVersion = null,
        string? targetVersion = null,
        string? channel = null,
        string? manifestUrl = null,
        string? campaignId = null,
        string? commandId = null,
        string? artifactSha256 = null,
        string? errorCode = null,
        string? errorMessage = null,
        int? msiExitCode = null,
        bool? requiresReboot = null,
        bool markChecked = false,
        string? installerResultId = null,
        string? attemptId = null,
        long? sequence = null,
        int? retryCount = null,
        string? retryAfterUtc = null,
        bool? quarantined = null)
        => this with
        {
            State = state,
            CurrentVersion = NullIfBlank(currentVersion) ?? CurrentVersion,
            TargetVersion = NullIfBlank(targetVersion) ?? (ChangesRequest(campaignId, commandId) ? null : TargetVersion),
            Channel = NullIfBlank(channel) ?? Channel,
            ManifestUrl = NullIfBlank(manifestUrl) ?? ManifestUrl,
            CampaignId = NullIfBlank(campaignId) ?? (ChangesRequest(campaignId, commandId) ? null : CampaignId),
            CommandId = NullIfBlank(commandId) ?? (ChangesRequest(campaignId, commandId) ? null : CommandId),
            ArtifactSha256 = NullIfBlank(artifactSha256) ?? (ChangesRequest(campaignId, commandId) ? null : ArtifactSha256),
            ReleaseId = ChangesRequest(campaignId, commandId) ? null : ReleaseId,
            LastCheckedUtc = markChecked ? Now() : LastCheckedUtc,
            LastTransitionUtc = Now(),
            LastErrorCode = NullIfBlank(errorCode),
            LastErrorMessage = RedactMessage(errorMessage),
            MsiExitCode = msiExitCode,
            RequiresReboot = requiresReboot ?? RequiresReboot,
            LastInstallerResultId = NullIfBlank(installerResultId) ?? LastInstallerResultId,
            AttemptId = NullIfBlank(attemptId) ?? (ChangesRequest(campaignId, commandId) ? null : AttemptId),
            Sequence = sequence ?? (ChangesRequest(campaignId, commandId) ? 0 : Sequence),
            RetryCount = retryCount ?? RetryCount,
            RetryAfterUtc = NullIfBlank(retryAfterUtc) ?? RetryAfterUtc,
            Quarantined = quarantined ?? Quarantined,
        };

    private bool ChangesRequest(string? campaignId, string? commandId)
        => NullIfBlank(campaignId) is { } campaign && campaign != CampaignId ||
           NullIfBlank(commandId) is { } command && command != CommandId;

    public IReadOnlyDictionary<string, object?> ToHeartbeatStatus()
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema_version"] = "agent.update.status.v2",
            ["state"] = State,
            ["current_version"] = CurrentVersion,
            ["target_version"] = TargetVersion,
            ["channel"] = Channel,
            ["campaign_id"] = CampaignId,
            ["command_id"] = CommandId,
            ["artifact_sha256"] = ArtifactSha256,
            ["last_checked_utc"] = LastCheckedUtc,
            ["last_transition_utc"] = LastTransitionUtc,
            ["last_error_code"] = LastErrorCode,
            ["msi_exit_code"] = MsiExitCode,
            ["requires_reboot"] = RequiresReboot,
            ["attempt_id"] = AttemptId,
            ["sequence"] = Sequence == 0 ? null : Sequence,
            ["release_id"] = ReleaseId,
            ["report_sequence"] = ReportSequence,
            ["policy"] = Policy,
            ["retry_count"] = RetryCount,
            ["next_retry_utc"] = RetryAfterUtc,
            ["health_state"] = HealthState,
            ["rollback_state"] = RollbackState,
            ["quarantined"] = Quarantined ? true : null,
        };
        foreach (var key in payload.Where(item => item.Value is null).Select(item => item.Key).ToArray())
            payload.Remove(key);
        return payload;
    }

    public IReadOnlyDictionary<string, object?> ToCommandResultPayload()
        // A report sequence denotes exactly one public payload across both transports.
        => ToHeartbeatStatus();

    private static string? NullIfBlank(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string? RedactMessage(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var redacted = SanitizeMessage(value);
        return redacted.Length <= 300 ? redacted : redacted[..300];
    }

    public static string SanitizeMessage(string value)
    {
        var redacted = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        redacted = Regex.Replace(redacted, "(?i)(?:[a-z]:\\\\|\\\\\\\\)[^<>\\\"\\r\\n]*", "<path>");
        redacted = Regex.Replace(redacted, @"https?://[^\s]+", "<url>");
        return redacted;
    }

    private static string Now()
        => DateTimeOffset.UtcNow.ToString("O");
}

public sealed record AgentUpdateInstallerResult(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("result_id")] string ResultId,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("recorded_at_utc")] string RecordedAtUtc,
    [property: JsonPropertyName("msi_exit_code")] int? MsiExitCode,
    [property: JsonPropertyName("requires_reboot")] bool RequiresReboot,
    [property: JsonPropertyName("error_code")] string? ErrorCode,
    [property: JsonPropertyName("error_message")] string? ErrorMessage,
    [property: JsonPropertyName("msi_log_path")] string? MsiLogPath,
    [property: JsonPropertyName("attempt_id")] string? AttemptId = null,
    [property: JsonPropertyName("retry_count")] int RetryCount = 0,
    [property: JsonPropertyName("retry_after_utc")] string? RetryAfterUtc = null,
    [property: JsonPropertyName("quarantined")] bool Quarantined = false)
{
    public const string CurrentSchemaVersion = "agent.update.installer_result.v1";

    public static AgentUpdateInstallerResult FromMsiExitCode(
        int exitCode,
        string? errorMessage,
        string? msiLogPath)
    {
        var (state, errorCode, requiresReboot) = exitCode switch
        {
            0 => (AgentUpdateStates.HealthPending, (string?)null, false),
            3010 => (AgentUpdateStates.PendingReboot, AgentUpdateErrorCodes.RebootRequired, true),
            1618 => (AgentUpdateStates.RetryableBusy, AgentUpdateErrorCodes.InstallerBusy, false),
            1602 => (AgentUpdateStates.Failed, AgentUpdateErrorCodes.UacCancelled, false),
            _ => (AgentUpdateStates.Failed, AgentUpdateErrorCodes.MsiFailed, false),
        };
        return new(
            CurrentSchemaVersion,
            Guid.NewGuid().ToString("N"),
            state,
            DateTimeOffset.UtcNow.ToString("O"),
            exitCode,
            requiresReboot,
            errorCode,
            errorMessage,
            msiLogPath);
    }

    public static AgentUpdateInstallerResult Failure(Exception ex)
        => new(
            CurrentSchemaVersion,
            Guid.NewGuid().ToString("N"),
            AgentUpdateStates.Failed,
            DateTimeOffset.UtcNow.ToString("O"),
            null,
            false,
            AgentUpdateErrorCodes.Unknown,
            AgentUpdateState.SanitizeMessage(ex.Message),
            null);
}
