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

    public DurableAgentLifecycleStateStore(string? path = null)
    {
        _path = string.IsNullOrWhiteSpace(path) ? GetDefaultPath() : System.IO.Path.GetFullPath(path);
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
                if (payload is null || !string.Equals(payload.SchemaVersion, SchemaVersion, StringComparison.Ordinal))
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
                    payload.UpdatedAtUtc));
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
        ArgumentNullException.ThrowIfNull(snapshot);
        var normalized = AgentLifecycleStatePolicy.Normalize(snapshot);
        var payload = new LifecyclePayload(
            SchemaVersion,
            normalized.State.ToString(),
            normalized.ReasonCode,
            normalized.LastRequestId,
            normalized.NextAttemptUtc,
            normalized.GenericAuthFailureCount,
            normalized.EffectiveUpdatedAtUtc);
        var json = JsonSerializer.Serialize(payload, JsonOpts);

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            EnsureProtectedPath();

            var tempPath = $"{_path}.{Guid.NewGuid():N}.tmp";
            try
            {
                await File.WriteAllTextAsync(tempPath, json, System.Text.Encoding.UTF8, ct).ConfigureAwait(false);
                if (OperatingSystem.IsWindows())
                    ProtectFile(tempPath);
                File.Move(tempPath, _path, overwrite: true);
                if (OperatingSystem.IsWindows())
                    ProtectFile(_path);
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

    private static AgentLifecycleSnapshot CorruptState()
        => new(
            State: AgentLifecycleState.BlockedConfig,
            ReasonCode: "lifecycle_state_invalid",
            LastRequestId: null,
            NextAttemptUtc: null,
            GenericAuthFailureCount: 0,
            UpdatedAtUtc: DateTimeOffset.UtcNow);

    private void EnsureProtectedPath()
    {
        var directory = System.IO.Path.GetDirectoryName(_path);
        if (string.IsNullOrWhiteSpace(directory))
            throw ProtectionFailure();

        try
        {
            if (OperatingSystem.IsWindows())
                EnsureNoReparsePoints(directory);

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

    private static void ProtectDirectory(string directoryPath)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(system);
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(directoryPath).SetAccessControl(security);
    }

    private static void ProtectFile(string filePath)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(system);
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
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
        [property: JsonPropertyName("updated_at_utc")] DateTimeOffset UpdatedAtUtc);
}
