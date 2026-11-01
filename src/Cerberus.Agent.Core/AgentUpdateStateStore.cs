using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

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
