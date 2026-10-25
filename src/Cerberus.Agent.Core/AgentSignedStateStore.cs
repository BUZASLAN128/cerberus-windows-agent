using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

/// <summary>A signed revoke that was applied but whose DONE result has not reached a final outcome yet.</summary>
public sealed record AgentPendingRevoke(
    [property: JsonPropertyName("command_id")] string CommandId,
    [property: JsonPropertyName("reason_code")] string ReasonCode);

/// <summary>Signed state applied from <c>agent_state</c> envelopes (contract v1 (b)) for one registration.</summary>
public sealed record AgentSignedState(
    [property: JsonPropertyName("agent_id")] string AgentId,
    [property: JsonPropertyName("state_seq")] long StateSeq,
    [property: JsonPropertyName("quarantine_active")] bool QuarantineActive,
    [property: JsonPropertyName("registration_state")] string? RegistrationState,
    [property: JsonPropertyName("pending_revoke")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    AgentPendingRevoke? PendingRevoke = null,
    [property: JsonPropertyName("reset")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? Reset = null)
{
    /// <summary>The <see cref="Reset"/> value of a quarantined replacement written after a corrupt file was set aside.</summary>
    public const string ResetUnreadable = "unreadable";

    /// <summary>The state of a registration that has no signed state yet.</summary>
    public static AgentSignedState Empty(string agentId) => new(agentId, 0, false, null);
}

/// <summary>
/// Durable signed-state store: <c>&lt;DataDir&gt;\Privileged\agent-state.v1.json</c>, one record bound to the
/// <c>agent_id</c> it was written for. A record of another agent id reads as empty and the next
/// write replaces it, so a re-enrolled agent starts at <c>state_seq</c> 0 without quarantine.
/// An unreadable or corrupt file is set aside and replaced by a quarantined state carrying
/// <c>"reset": "unreadable"</c>, so the quarantine survives a restart; it reads as quarantined until a
/// signed write succeeds (fail closed). If the replacement cannot be written, the quarantine lasts for the process. On a machine path (see <see cref="ProtectedMachineFile"/>) an untrusted
/// directory, owner, DACL, directory or reparse point at the path reads as quarantined as well and is
/// never parsed; the next signed write replaces the object.
/// </summary>
public sealed class AgentSignedStateStore
{
    public const string FileName = "agent-state.v1.json";
    private const long MaxFileBytes = 64 * 1024;
    private const string Schema = "cerberus.agent-state.v1";

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    private readonly object _gate = new();
    private readonly string _path;
    private readonly ProtectedMachineFile _file;
    private readonly IAgentLogger _log;
    private AgentSignedState? _state;
    private string? _currentAgentId;
    private bool _loaded;
    private bool _unreadable;

    /// <param name="enforceFileProvenance">Also demands a SYSTEM/Administrators owner and a DACL without untrusted
    /// writers on a path outside <c>Privileged</c> (always on inside it).</param>
    public AgentSignedStateStore(string path, IAgentLogger? log = null, bool enforceFileProvenance = false)
    {
        _path = string.IsNullOrWhiteSpace(path) ? throw new ArgumentException("Path is required.", nameof(path)) : path;
        _file = new ProtectedMachineFile(_path, enforceFileProvenance);
        _log = log ?? NullAgentLogger.Instance;
    }

    /// <summary>The store path under <c>&lt;DataDir&gt;\Privileged</c>.</summary>
    public static string DefaultPath() => ProtectedMachineFile.DefaultPath(FileName);

    /// <summary>
    /// Wraps the current-<c>agent_id</c> provider so every id it returns becomes the id that
    /// <see cref="IsQuarantined()"/> checks. Pass the wrapped provider to the execution queue and
    /// the <c>agent_state</c> handler; both read it before any quarantine check.
    /// </summary>
    public Func<CancellationToken, Task<string>> Track(Func<CancellationToken, Task<string>> currentAgentId)
    {
        ArgumentNullException.ThrowIfNull(currentAgentId);
        return async ct =>
        {
            var agentId = await currentAgentId(ct).ConfigureAwait(false);
            lock (_gate)
                _currentAgentId = agentId;
            return agentId;
        };
    }

    /// <summary>
    /// The execution queue's quarantine delegate: true while signed quarantine is active or a signed
    /// revoke waits for its result, for the agent id last seen by <see cref="Track"/>.
    /// </summary>
    public bool IsQuarantined()
    {
        lock (_gate)
        {
            EnsureLoaded();
            if (_unreadable)
                return true;
            var agentId = _currentAgentId ?? _state?.AgentId;
            return agentId is not null && IsQuarantinedLocked(agentId);
        }
    }

    public bool IsQuarantined(string agentId)
    {
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        lock (_gate)
        {
            EnsureLoaded();
            return _unreadable || IsQuarantinedLocked(agentId);
        }
    }

    /// <summary>
    /// The persisted state of <paramref name="agentId"/>; empty when the record belongs to another agent or is a
    /// reset marker (the marker quarantines through <see cref="IsQuarantined(string)"/> and is never a base for a signed write).
    /// </summary>
    public AgentSignedState Load(string agentId)
    {
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        lock (_gate)
        {
            EnsureLoaded();
            return _state is { Reset: null } && string.Equals(_state.AgentId, agentId, StringComparison.Ordinal)
                ? _state
                : AgentSignedState.Empty(agentId);
        }
    }

    /// <summary>
    /// Replaces the whole record (temp file, flush, atomic replace) and clears any reset marker: a signed write
    /// lifts the quarantine of a corrupt file. On failure nothing changes.
    /// </summary>
    public bool TrySave(AgentSignedState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentException.ThrowIfNullOrEmpty(state.AgentId);
        state = state with { Reset = null };
        lock (_gate)
        {
            EnsureLoaded();
            if (!TryPersist(state))
                return false;
            if (_state is not null && !string.Equals(_state.AgentId, state.AgentId, StringComparison.Ordinal))
                _log.Info("Signed agent state rebound to a new agent id.");
            _state = state;
            _unreadable = false;
            return true;
        }
    }

    /// <summary>
    /// Drops the pending revoke of <paramref name="commandId"/> once the lifecycle write ran, leaving every other
    /// field as stored now. True when nothing was pending for that command or the write succeeded.
    /// </summary>
    public bool TryClearPendingRevoke(string agentId, string commandId)
    {
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        lock (_gate)
        {
            EnsureLoaded();
            return _state is { PendingRevoke: { } pending } state
                   && string.Equals(state.AgentId, agentId, StringComparison.Ordinal)
                   && string.Equals(pending.CommandId, commandId, StringComparison.Ordinal)
                ? TrySave(state with { PendingRevoke = null })
                : true;
        }
    }

    private bool IsQuarantinedLocked(string agentId)
        => _state is { } state && string.Equals(state.AgentId, agentId, StringComparison.Ordinal)
           && (state.QuarantineActive || state.PendingRevoke is not null);

    private void EnsureLoaded()
    {
        if (_loaded)
            return;
        _loaded = true;
        try
        {
            _file.ValidateDirectory();
            if (!_file.Exists())
                return;
            _file.ValidateFile();
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex))
        {
            // Never parse or move an object that fails provenance: a moved file would keep its DACL.
            _unreadable = true;
            _log.Error($"Signed agent state storage is untrusted ({ex.GetType().Name}); quarantined until the next signed state.");
            return;
        }

        if (TryRead(out var state))
        {
            _state = state;
            // A reset marker quarantines whatever agent id is current until a signed write replaces it.
            _unreadable = state!.Reset is not null;
            return;
        }

        _unreadable = true;
        var corruptPath = $"{_path}.corrupt-{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";
        try
        {
            File.Move(_path, corruptPath, overwrite: true);
            _log.Warn($"Signed agent state was unreadable; moved to {Path.GetFileName(corruptPath)}; quarantined until the next signed state.");
            // Without a file a restart would lose the quarantine; on failure the in-memory quarantine stays.
            TryPersist(new AgentSignedState(_currentAgentId ?? "unknown", 0, true, null, null, AgentSignedState.ResetUnreadable));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Error($"Signed agent state unreadable and could not be set aside: {ex.GetType().Name}; quarantined until the next signed state.");
        }
    }

    private bool TryRead(out AgentSignedState? state)
    {
        state = null;
        try
        {
            if (new FileInfo(_path).Length > MaxFileBytes)
                return false;
            var file = JsonSerializer.Deserialize<StoreFile>(File.ReadAllBytes(_path), JsonOpts);
            if (file is null || file.Schema != Schema || file.State is not { } loaded
                || string.IsNullOrEmpty(loaded.AgentId) || loaded.StateSeq < 0
                || loaded.RegistrationState is not (null or "pending_claim" or "claimed")
                || (loaded.PendingRevoke is { } revoke
                    && (string.IsNullOrEmpty(revoke.CommandId) || revoke.ReasonCode is not ("agent_revoked" or "agent_deactivated")))
                || loaded.Reset is not (null or AgentSignedState.ResetUnreadable))
                return false;
            state = loaded;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return false;
        }
    }

    private bool TryPersist(AgentSignedState state)
    {
        var tempPath = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            _file.EnsureDirectory();
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new StoreFile(Schema, state), JsonOpts);
            using (var stream = _file.CreateTemp(tempPath))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, _path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex))
        {
            _log.Error($"Signed agent state write failed: {ex.GetType().Name}.");
            try
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
            catch (Exception cleanup) when (cleanup is IOException or UnauthorizedAccessException)
            {
                // The temp name is unique; a leftover file is never read.
            }

            return false;
        }
    }

    private sealed record StoreFile(
        [property: JsonPropertyName("schema")] string Schema,
        [property: JsonPropertyName("state")] AgentSignedState? State);
}
