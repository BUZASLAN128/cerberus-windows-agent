using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Security;

/// <summary>
/// Stores non-secret lifecycle state in an ACL-protected machine file. This is
/// deliberately separate from the DPAPI credential payload so a paused or
/// retired service can read its local state without decrypting credentials.
/// </summary>
public sealed class DurableAgentLifecycleStateStore : IAgentLifecycleStateStore
{
    private const string SchemaVersion = "cerberus-agent-lifecycle.v1";
    private const int MaxStateFileBytes = 16 * 1024;
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly bool _production;

    public DurableAgentLifecycleStateStore(string? path = null)
    {
        _path = string.IsNullOrWhiteSpace(path) ? GetDefaultPath() : System.IO.Path.GetFullPath(path);
        _production = string.Equals(_path, GetDefaultPath(), StringComparison.OrdinalIgnoreCase);
        EnsureProtectedPath();
    }

    public string Path => _path;

    public static string GetDefaultPath()
        => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CerberusAgent",
            "Privileged",
            "lifecycle-state.json");

    public async Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Re-check the machine boundary on every operation so a path
            // replacement after construction cannot re-enable writable state.
            EnsureProtectedPath();
            if (!File.Exists(_path))
                return new AgentLifecycleSnapshot();

            try
            {
                if (new FileInfo(_path).Length > MaxStateFileBytes)
                    return CorruptState();
                var raw = await File.ReadAllTextAsync(_path, ct).ConfigureAwait(false);
                var payload = JsonSerializer.Deserialize<LifecyclePayload>(raw, JsonOpts);
                if (payload is null || payload.Generation < 0 || payload.Revision < 0 || !string.Equals(payload.SchemaVersion, SchemaVersion, StringComparison.Ordinal))
                    return CorruptState();

                if (!Enum.TryParse<AgentLifecycleState>(payload.State, ignoreCase: true, out var state) ||
                    !Enum.IsDefined(state))
                    return CorruptState();

                return AgentLifecycleStatePolicy.Normalize(new AgentLifecycleSnapshot(
                    state,
                    payload.ReasonCode,
                    payload.LastRequestId,
                    payload.NextAttemptUtc,
                    payload.GenericAuthFailureCount,
                    payload.UpdatedAtUtc)
                {
                    Generation = payload.Generation,
                    Revision = payload.Revision,
                    QuiescenceComplete = payload.QuiescenceComplete ?? AgentLifecycleStates.AllowsAutomaticNetwork(state),
                    TransientFailureCount = payload.TransientFailureCount,
                    LastEnrollmentNonce = payload.LastEnrollmentNonce,
                });
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Corrupt or tampered state must fail closed rather than
                // silently restoring automatic network activity.
                return CorruptState();
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct)
    {
        if (await TrySaveAsync(snapshot, snapshot.Revision, ct).ConfigureAwait(false) is null)
            throw new InvalidOperationException("Lifecycle generation changed.");
    }

    public async Task<AgentLifecycleSnapshot?> TrySaveAsync(AgentLifecycleSnapshot snapshot, long expectedRevision, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (_production && (!OperatingSystem.IsWindows() || !WindowsIdentity.GetCurrent().IsSystem))
            throw new UnauthorizedAccessException("Only the agent service can change machine lifecycle state.");
        // The launch fence must precede the lifecycle lock. Release both before
        // invoking updater cleanup; the runner holds this only through Process.Start.
        using var launchFence = AgentLifecycleStates.IsDormant(snapshot.State)
            ? await AgentUpdateLaunchFence.AcquireAsync(ct, _production ? null : System.IO.Path.GetDirectoryName(_path)).ConfigureAwait(false)
            : null;
        await using var processLock = await AcquireProcessLockAsync(ct).ConfigureAwait(false);
        var current = await LoadAsync(ct).ConfigureAwait(false);
        if (current.Revision != expectedRevision)
            return null;
        var normalized = AgentLifecycleStatePolicy.ForCommit(current, snapshot);
        var payload = new LifecyclePayload(
            SchemaVersion,
            normalized.State.ToString(),
            normalized.ReasonCode,
            normalized.LastRequestId,
            normalized.NextAttemptUtc,
            normalized.GenericAuthFailureCount,
            normalized.EffectiveUpdatedAtUtc,
            normalized.Generation,
            normalized.QuiescenceComplete,
            normalized.TransientFailureCount,
            normalized.Revision,
            normalized.LastEnrollmentNonce);
        var json = JsonSerializer.Serialize(payload, JsonOpts);

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureProtectedPath();

            var tempPath = $"{_path}.{Guid.NewGuid():N}.tmp";
            try
            {
                await using (var output = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write,
                    FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await output.WriteAsync(System.Text.Encoding.UTF8.GetBytes(json), ct).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }
                if (OperatingSystem.IsWindows())
                    ProtectFile(tempPath);
                File.Move(tempPath, _path, overwrite: true);
                if (OperatingSystem.IsWindows())
                    ProtectFile(_path);
                return normalized;
            }
            finally
            {
                try
                {
                    if (File.Exists(tempPath))
                        File.Delete(tempPath);
                }
                catch
                {
                    // A stale temp file contains only non-secret state and is
                    // never used as the canonical path.
                }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<FileStream> AcquireProcessLockAsync(CancellationToken ct)
    {
        EnsureProtectedPath();
        var lockPath = _path + ".lock";
        var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (File.Exists(lockPath) && File.GetAttributes(lockPath).HasFlag(FileAttributes.ReparsePoint))
                    throw ProtectionFailure();
                return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(25, ct).ConfigureAwait(false);
            }
        }
    }

    public async Task<bool> ExecuteIfCurrentAsync(long expectedGeneration, Func<CancellationToken, Task> action, CancellationToken ct)
    {
        if (_production && (!OperatingSystem.IsWindows() || !WindowsIdentity.GetCurrent().IsSystem))
            throw new UnauthorizedAccessException("Only the agent service can change machine credentials.");
        await using var processLock = await AcquireProcessLockAsync(ct).ConfigureAwait(false);
        if ((await LoadAsync(ct).ConfigureAwait(false)).Generation != expectedGeneration)
            return false;
        await action(ct).ConfigureAwait(false);
        return true;
    }

    private static AgentLifecycleSnapshot CorruptState()
        => new(
            State: AgentLifecycleState.BlockedConfig,
            ReasonCode: "lifecycle_state_invalid",
            LastRequestId: null,
            NextAttemptUtc: null,
            GenericAuthFailureCount: 0,
            UpdatedAtUtc: DateTimeOffset.UtcNow) { QuiescenceComplete = false };

    private void EnsureProtectedPath()
    {
        var directory = System.IO.Path.GetDirectoryName(_path);
        if (string.IsNullOrWhiteSpace(directory))
            throw ProtectionFailure();

        try
        {
            if (OperatingSystem.IsWindows())
                EnsureNoReparsePoints(directory);

            if (_production && OperatingSystem.IsWindows() && !WindowsIdentity.GetCurrent().IsSystem)
            {
                // Readers never repair ACLs or create machine authority.
                if (!Directory.Exists(directory))
                    throw ProtectionFailure();
                if (File.Exists(_path) && File.GetAttributes(_path).HasFlag(FileAttributes.ReparsePoint))
                    throw ProtectionFailure();
                return;
            }

            Directory.CreateDirectory(directory);

            if (!OperatingSystem.IsWindows())
                return;

            EnsureNoReparsePoints(directory);
            ProtectDirectory(directory);
            ProtectExistingFile();
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch
        {
            // ACL/reparse failures are security failures, not corrupt state.
            // The caller must observe the error and keep the worker stopped.
            throw ProtectionFailure();
        }
    }

    private void ProtectExistingFile()
    {
        try
        {
            var attributes = File.GetAttributes(_path);
            if (attributes.HasFlag(FileAttributes.ReparsePoint))
                throw ProtectionFailure();

            ProtectFile(_path);
        }
        catch (FileNotFoundException)
        {
            // The canonical state file is created by SaveAsync.
        }
        catch (DirectoryNotFoundException)
        {
            // The canonical parent was checked/created immediately before this
            // call; a concurrent removal is handled as a protection failure.
            throw ProtectionFailure();
        }
    }

    private void ProtectDirectory(string directoryPath)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(_production ? system : WindowsIdentity.GetCurrent().User!);
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            _production ? new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) : WindowsIdentity.GetCurrent().User!,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(directoryPath).SetAccessControl(security);
    }

    private void ProtectFile(string filePath)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(_production ? system : WindowsIdentity.GetCurrent().User!);
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            _production ? new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) : WindowsIdentity.GetCurrent().User!,
            _production ? FileSystemRights.ReadAndExecute : FileSystemRights.FullControl,
            AccessControlType.Allow));
        new FileInfo(filePath).SetAccessControl(security);
    }

    private static void EnsureNoReparsePoints(string directoryPath)
    {
        try
        {
            var current = new DirectoryInfo(directoryPath);
            while (current is not null)
            {
                if (current.Exists && current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw ProtectionFailure();
                current = current.Parent;
            }
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch
        {
            throw ProtectionFailure();
        }
    }

    private static InvalidOperationException ProtectionFailure()
        => new("Cerberus agent lifecycle state protection could not be established.");

    private sealed record LifecyclePayload(
        [property: JsonPropertyName("schema_version")] string SchemaVersion,
        [property: JsonPropertyName("state")] string State,
        [property: JsonPropertyName("reason_code")] string? ReasonCode,
        [property: JsonPropertyName("last_request_id")] string? LastRequestId,
        [property: JsonPropertyName("next_attempt_utc")] DateTimeOffset? NextAttemptUtc,
        [property: JsonPropertyName("generic_auth_failure_count")] int GenericAuthFailureCount,
        [property: JsonPropertyName("updated_at_utc")] DateTimeOffset UpdatedAtUtc,
        [property: JsonPropertyName("generation")] long Generation = 0,
        [property: JsonPropertyName("quiescence_complete")] bool? QuiescenceComplete = null,
        [property: JsonPropertyName("transient_failure_count")] int TransientFailureCount = 0,
        [property: JsonPropertyName("revision")] long Revision = 0,
        [property: JsonPropertyName("last_enrollment_nonce")] string? LastEnrollmentNonce = null);
}
