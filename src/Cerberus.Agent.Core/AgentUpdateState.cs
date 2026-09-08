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
            AttemptId = NullIfBlank(attemptId) ?? AttemptId,
            Sequence = sequence ?? Sequence,
            RetryCount = retryCount ?? RetryCount,
            RetryAfterUtc = NullIfBlank(retryAfterUtc) ?? RetryAfterUtc,
            Quarantined = quarantined ?? Quarantined,
        };

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
        => await ReadPersistedAsync(ct).ConfigureAwait(false) ?? AgentUpdateState.NotChecked(currentVersion);

    private async Task<AgentUpdateState?> ReadPersistedAsync(CancellationToken ct)
    {
        try
        {
            ValidateStatePath();
            if (!File.Exists(StatePath))
                return null;
            if (new FileInfo(StatePath).Length is <= 0 or > AgentUpdateDurableFile.MaxBytes)
                throw new InvalidOperationException("Update state length is invalid.");
            var raw = await File.ReadAllTextAsync(StatePath, ct).ConfigureAwait(false);
            var state = JsonSerializer.Deserialize<AgentUpdateState>(raw, JsonOptions);
            if (state is null || state.SchemaVersion != AgentUpdateState.CurrentSchemaVersion || state.ReportSequence < 0)
                throw new InvalidOperationException("Update state is invalid.");
            return state;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new InvalidOperationException("Update state could not be read.", ex);
        }
    }

    public async Task WriteAsync(AgentUpdateState state, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(StatePath);
        if (!string.IsNullOrWhiteSpace(dir))
            EnsureStateDirectory(dir);
        ValidateStatePath();

        // This sequence belongs to the agent report stream, not to an attempt.
        using var reportLock = new FileStream(StatePath + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var previous = await ReadAsync(state.CurrentVersion, ct).ConfigureAwait(false);
        if (state with { ReportSequence = previous.ReportSequence, LastTransitionUtc = previous.LastTransitionUtc } == previous)
            return;
        var next = state with { ReportSequence = checked(previous.ReportSequence + 1) };
        AgentUpdateDurableFile.Write(StatePath, dir!, next);
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
        string? installerResultId = null,
        string? attemptId = null,
        long? sequence = null,
        int? retryCount = null,
        string? retryAfterUtc = null,
        bool? quarantined = null)
    {
        var next = await BuildTransitionAsync(
            state,
            currentVersion,
            ct,
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
            installerResultId,
            attemptId,
            sequence,
            retryCount,
            retryAfterUtc,
            quarantined).ConfigureAwait(false);
        await WriteAsync(next, ct).ConfigureAwait(false);
        return await ReadAsync(currentVersion, ct).ConfigureAwait(false);
    }

    public async Task<AgentUpdateState> TryWriteTransitionAsync(
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
        string? installerResultId = null,
        string? attemptId = null,
        long? sequence = null,
        int? retryCount = null,
        string? retryAfterUtc = null,
        bool? quarantined = null)
    {
        var next = await BuildTransitionAsync(
            state,
            currentVersion,
            ct,
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
            installerResultId,
            attemptId,
            sequence,
            retryCount,
            retryAfterUtc,
            quarantined).ConfigureAwait(false);
        try
        {
            await WriteAsync(next, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }

        return next;
    }

    private async Task<AgentUpdateState> BuildTransitionAsync(
        string state,
        string? currentVersion,
        CancellationToken ct,
        string? targetVersion,
        string? channel,
        string? manifestUrl,
        string? campaignId,
        string? commandId,
        string? artifactSha256,
        string? errorCode,
        string? errorMessage,
        int? msiExitCode,
        bool? requiresReboot,
        bool markChecked,
        string? installerResultId,
        string? attemptId,
        long? sequence,
        int? retryCount,
        string? retryAfterUtc,
        bool? quarantined)
    {
        var existing = await ReadAsync(currentVersion, ct).ConfigureAwait(false);
        return existing.Transition(
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
            installerResultId,
            attemptId,
            sequence,
            retryCount,
            retryAfterUtc,
            quarantined);
    }

    /// <summary>Returns only a durable ordered report; an untouched agent has no update report yet.</summary>
    public async Task<AgentUpdateState?> ReconcileInstallerResultAsync(string? currentVersion, CancellationToken ct)
    {
        var state = await ReadPersistedAsync(ct).ConfigureAwait(false);
        var result = await ReadInstallerResultAsync(ct).ConfigureAwait(false);
        if (result is null || string.Equals(result.ResultId, state?.LastInstallerResultId, StringComparison.Ordinal))
            return state;

        state ??= AgentUpdateState.NotChecked(currentVersion);
        if (state.AttemptId is not null && result.AttemptId != state.AttemptId)
            throw new InvalidOperationException("Installer result does not match the active attempt.");
        var nextState = result.State == AgentUpdateStates.Applied ? AgentUpdateStates.HealthPending : result.State;
        var next = state.Transition(
            nextState,
            currentVersion,
            errorCode: result.ErrorCode,
            errorMessage: result.ErrorMessage,
            msiExitCode: result.MsiExitCode,
            requiresReboot: result.RequiresReboot,
            installerResultId: result.ResultId,
            attemptId: result.AttemptId,
            retryCount: result.RetryCount,
            retryAfterUtc: result.RetryAfterUtc,
            quarantined: result.Quarantined);
        await WriteAsync(next, ct).ConfigureAwait(false);
        return await ReadPersistedAsync(ct).ConfigureAwait(false);
    }

    public async Task WriteInstallerResultAsync(AgentUpdateInstallerResult result, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(InstallerResultPath);
        if (!string.IsNullOrWhiteSpace(dir))
            EnsureStateDirectory(dir);
        ValidateStatePath(InstallerResultPath);

        var tempPath = $"{InstallerResultPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            var safeResult = result with
            {
                ErrorMessage = result.ErrorMessage is null ? null : AgentUpdateState.SanitizeMessage(result.ErrorMessage),
                MsiLogPath = null,
            };
            var json = JsonSerializer.Serialize(safeResult, JsonOptions);
            await File.WriteAllTextAsync(tempPath, json, ct).ConfigureAwait(false);
            File.Move(tempPath, InstallerResultPath, overwrite: true);
        }
        finally
        {
            TryDeleteFile(tempPath);
        }
    }

    public async Task<AgentUpdateInstallerResult?> ReadInstallerResultAsync(CancellationToken ct)
    {
        try
        {
            ValidateStatePath(InstallerResultPath);
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

    private void ValidateStatePath(string? path = null)
    {
        var target = path ?? StatePath;
        var root = AgentUpdateSecurity.DefaultPrivilegedRoot;
        if (AgentUpdateSecurity.IsUnderDirectory(target, root))
            AgentUpdateSecurity.ValidateTrustedPath(target, root, allowMissing: true);
    }

    private static void EnsureStateDirectory(string directory)
    {
        var root = AgentUpdateSecurity.DefaultPrivilegedRoot;
        if (string.Equals(
                AgentUpdateSecurity.NormalizeRoot(directory),
                AgentUpdateSecurity.NormalizeRoot(root),
                StringComparison.OrdinalIgnoreCase))
        {
            if (!AgentUpdateSecurity.IsLocalSystem())
                throw new UnauthorizedAccessException("Only the installed agent service may write update state.");
            AgentUpdateSecurity.EnsureProtectedRoot(root);
            return;
        }

        Directory.CreateDirectory(directory);
    }
}

public static class AgentUpdateSequenceStore
{
    private const string SequenceFileName = "highest-sequence.json";

    private sealed record AcceptedManifest(
        [property: JsonPropertyName("schema_version")] string SchemaVersion,
        [property: JsonPropertyName("highest_sequence")] long HighestSequence,
        [property: JsonPropertyName("manifest_digest")] string? ManifestDigest);

    public static long ReadHighest(string root)
    {
        var path = Path.Combine(AgentUpdateSecurity.NormalizeRoot(root), SequenceFileName);
        try
        {
            AgentUpdateSecurity.ValidateTrustedPath(path, root, allowMissing: true);
            if (!File.Exists(path))
                return 0;
            var record = AgentUpdateDurableFile.Read<AcceptedManifest>(path, root);
            if (record is null || record.SchemaVersion is not ("agent.update.sequence.v1" or "agent.update.sequence.v2") || record.HighestSequence <= 0)
                throw new InvalidOperationException("Update sequence state is invalid.");
            return record.HighestSequence;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new InvalidOperationException("Update sequence state could not be read.", ex);
        }
    }

    /// <summary>Accept the signed canonical payload before using it. A same-sequence payload may only resume byte-identical semantics.</summary>
    public static void Accept(string root, long sequence, string digest)
    {
        if (sequence <= 0 || digest.Length != 64 || !digest.All(Uri.IsHexDigit))
            throw new InvalidOperationException("Update manifest acceptance is invalid.");
        using var gate = AgentUpdateSecurity.AcquireGlobalLock(root);
        var path = Path.Combine(AgentUpdateSecurity.NormalizeRoot(root), SequenceFileName);
        var current = ReadHighest(root);
        var accepted = AgentUpdateDurableFile.Read<AcceptedManifest>(path, root);
        if (sequence < current || (sequence == current &&
            !string.Equals(accepted?.ManifestDigest, digest, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Update manifest sequence rollback or equivocation denied.");
        if (sequence == current)
            return;
        AgentUpdateDurableFile.Write(path, root, new AcceptedManifest("agent.update.sequence.v2", sequence, digest.ToLowerInvariant()));
    }

    public static void RequireAccepted(string root, long sequence, string digest)
    {
        var path = Path.Combine(AgentUpdateSecurity.NormalizeRoot(root), SequenceFileName);
        var current = ReadHighest(root);
        var accepted = AgentUpdateDurableFile.Read<AcceptedManifest>(path, root);
        if (sequence != current || !string.Equals(accepted?.ManifestDigest, digest, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update attempt does not match accepted manifest trust.");
    }


}
