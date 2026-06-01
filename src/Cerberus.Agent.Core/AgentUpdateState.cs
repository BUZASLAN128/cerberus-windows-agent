using System.Text.Json;
using System.Text.Json.Serialization;

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

    public static bool CanApply(string? state)
        => string.Equals(state, Available, StringComparison.Ordinal) ||
           string.Equals(state, Staged, StringComparison.Ordinal) ||
           string.Equals(state, Prompting, StringComparison.Ordinal);
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
    [property: JsonPropertyName("last_installer_result_id")] string? LastInstallerResultId)
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
        string? installerResultId = null)
        => this with
        {
            State = state,
            CurrentVersion = NullIfBlank(currentVersion) ?? CurrentVersion,
            TargetVersion = NullIfBlank(targetVersion) ?? TargetVersion,
            Channel = NullIfBlank(channel) ?? Channel,
            ManifestUrl = NullIfBlank(manifestUrl) ?? ManifestUrl,
            CampaignId = NullIfBlank(campaignId) ?? CampaignId,
            CommandId = NullIfBlank(commandId) ?? CommandId,
            ArtifactSha256 = NullIfBlank(artifactSha256) ?? ArtifactSha256,
            LastCheckedUtc = markChecked ? Now() : LastCheckedUtc,
            LastTransitionUtc = Now(),
            LastErrorCode = NullIfBlank(errorCode),
            LastErrorMessage = RedactMessage(errorMessage),
            MsiExitCode = msiExitCode,
            RequiresReboot = requiresReboot ?? RequiresReboot,
            LastInstallerResultId = NullIfBlank(installerResultId) ?? LastInstallerResultId,
        };

    public IReadOnlyDictionary<string, object?> ToHeartbeatStatus()
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema_version"] = "agent.update.status.v1",
            ["state"] = State,
            ["current_version"] = CurrentVersion,
            ["target_version"] = TargetVersion,
            ["channel"] = Channel,
            ["manifest_url"] = ManifestUrl,
            ["campaign_id"] = CampaignId,
            ["command_id"] = CommandId,
            ["artifact_sha256"] = ArtifactSha256,
            ["last_checked_utc"] = LastCheckedUtc,
            ["last_transition_utc"] = LastTransitionUtc,
            ["last_error_code"] = LastErrorCode,
            ["last_error_message"] = LastErrorMessage,
            ["msi_exit_code"] = MsiExitCode,
            ["requires_reboot"] = RequiresReboot,
        };
        foreach (var key in payload.Where(item => item.Value is null).Select(item => item.Key).ToArray())
            payload.Remove(key);
        return payload;
    }

    public IReadOnlyDictionary<string, object?> ToCommandResultPayload()
    {
        var payload = new Dictionary<string, object?>(ToHeartbeatStatus(), StringComparer.Ordinal)
        {
            ["schema_version"] = "agent.update.result.v1",
        };
        payload.Remove("manifest_url");
        payload.Remove("command_id");
        payload.Remove("last_transition_utc");
        payload.Remove("last_checked_utc");
        payload.Remove("last_error_message");
        return payload;
    }

    private static string? NullIfBlank(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string? RedactMessage(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var redacted = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return redacted.Length <= 300 ? redacted : redacted[..300];
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
    [property: JsonPropertyName("msi_log_path")] string? MsiLogPath)
{
    public const string CurrentSchemaVersion = "agent.update.installer_result.v1";

    public static AgentUpdateInstallerResult FromMsiExitCode(
        int exitCode,
        string? errorMessage,
        string? msiLogPath)
    {
        var (state, errorCode, requiresReboot) = exitCode switch
        {
            0 => (AgentUpdateStates.Applied, (string?)null, false),
            3010 => (AgentUpdateStates.Applied, AgentUpdateErrorCodes.RebootRequired, true),
            1618 => (AgentUpdateStates.Failed, AgentUpdateErrorCodes.InstallerBusy, false),
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
            ex.Message,
            null);
}

public sealed class AgentUpdateStateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public AgentUpdateStateStore(string statePath, string installerResultPath)
    {
        StatePath = statePath;
        InstallerResultPath = installerResultPath;
    }

    public string StatePath { get; }
    public string InstallerResultPath { get; }

    public static AgentUpdateStateStore CreateDefault()
        => new(
            Path.Combine(AgentUpdateStager.DefaultStagingRoot, "update-state.json"),
            Path.Combine(AgentUpdateStager.DefaultStagingRoot, "update-result.json"));

    public async Task<AgentUpdateState> ReadAsync(string? currentVersion, CancellationToken ct)
    {
        try
        {
            if (!File.Exists(StatePath))
                return AgentUpdateState.NotChecked(currentVersion);
            var raw = await File.ReadAllTextAsync(StatePath, ct).ConfigureAwait(false);
            var state = JsonSerializer.Deserialize<AgentUpdateState>(raw, JsonOptions);
            return state is null || !string.Equals(state.SchemaVersion, AgentUpdateState.CurrentSchemaVersion, StringComparison.Ordinal)
                ? AgentUpdateState.NotChecked(currentVersion)
                : state;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return AgentUpdateState.NotChecked(currentVersion);
        }
    }

    public async Task WriteAsync(AgentUpdateState state, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(StatePath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        var tempPath = $"{StatePath}.{Guid.NewGuid():N}.tmp";
        try
        {
            var json = JsonSerializer.Serialize(state, JsonOptions);
            await File.WriteAllTextAsync(tempPath, json, ct).ConfigureAwait(false);
            File.Move(tempPath, StatePath, overwrite: true);
        }
        finally
        {
            TryDeleteFile(tempPath);
        }
    }

    public async Task<AgentUpdateState> WriteTransitionAsync(
        string state,
        string? currentVersion,
        CancellationToken ct,
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
        string? installerResultId = null)
    {
        var existing = await ReadAsync(currentVersion, ct).ConfigureAwait(false);
        var next = existing.Transition(
            state,
            currentVersion,
            targetVersion,
            channel,
            manifestUrl,
            campaignId,
            commandId,
            artifactSha256,
            errorCode,
            errorMessage,
            msiExitCode,
            requiresReboot,
            markChecked,
            installerResultId);
        await WriteAsync(next, ct).ConfigureAwait(false);
        return next;
    }

    public async Task<AgentUpdateState> ReconcileInstallerResultAsync(string? currentVersion, CancellationToken ct)
    {
        var state = await ReadAsync(currentVersion, ct).ConfigureAwait(false);
        var result = await ReadInstallerResultAsync(ct).ConfigureAwait(false);
        if (result is null || string.Equals(result.ResultId, state.LastInstallerResultId, StringComparison.Ordinal))
            return state;

        var nextState = string.Equals(result.State, AgentUpdateStates.Applied, StringComparison.Ordinal)
            ? AgentUpdateStates.Applied
            : AgentUpdateStates.Failed;
        var next = state.Transition(
            nextState,
            currentVersion,
            errorCode: result.ErrorCode,
            errorMessage: result.ErrorMessage,
            msiExitCode: result.MsiExitCode,
            requiresReboot: result.RequiresReboot,
            installerResultId: result.ResultId);
        await WriteAsync(next, ct).ConfigureAwait(false);
        return next;
    }

    public async Task WriteInstallerResultAsync(AgentUpdateInstallerResult result, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(InstallerResultPath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        var tempPath = $"{InstallerResultPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            var json = JsonSerializer.Serialize(result, JsonOptions);
            await File.WriteAllTextAsync(tempPath, json, ct).ConfigureAwait(false);
            File.Move(tempPath, InstallerResultPath, overwrite: true);
        }
        finally
        {
            TryDeleteFile(tempPath);
        }
    }

    private async Task<AgentUpdateInstallerResult?> ReadInstallerResultAsync(CancellationToken ct)
    {
        try
        {
            if (!File.Exists(InstallerResultPath))
                return null;
            var raw = await File.ReadAllTextAsync(InstallerResultPath, ct).ConfigureAwait(false);
            return JsonSerializer.Deserialize<AgentUpdateInstallerResult>(raw, JsonOptions);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
