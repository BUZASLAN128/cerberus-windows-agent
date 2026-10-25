using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

/// <summary>Signed state applied from <c>agent_state</c> envelopes (contract v1 (b)) for one registration.</summary>
public sealed record AgentSignedState(
    [property: JsonPropertyName("agent_id")] string AgentId,
    [property: JsonPropertyName("state_seq")] long StateSeq,
    [property: JsonPropertyName("quarantine_active")] bool QuarantineActive,
    [property: JsonPropertyName("registration_state")] string? RegistrationState)
{
    /// <summary>The state of a registration that has no signed state yet.</summary>
    public static AgentSignedState Empty(string agentId) => new(agentId, 0, false, null);
}

/// <summary>
/// Durable signed-state store: <c>&lt;DataDir&gt;\agent-state.v1.json</c>, one record bound to the
/// <c>agent_id</c> it was written for. A record of another agent id reads as empty and the next
/// write replaces it, so a re-enrolled agent starts at <c>state_seq</c> 0 without quarantine.
/// An unreadable or corrupt file is set aside and reads as quarantined until a signed write
/// succeeds (fail closed).
/// </summary>
public sealed class AgentSignedStateStore
{
    public const string FileName = "agent-state.v1.json";
    private const long MaxFileBytes = 64 * 1024;
    private const string Schema = "cerberus.agent-state.v1";

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    private readonly object _gate = new();
    private readonly string _path;
    private readonly IAgentLogger _log;
    private AgentSignedState? _state;
    private string? _currentAgentId;
    private string? _revokePendingAgentId;
    private bool _loaded;
    private bool _unreadable;

    public AgentSignedStateStore(string path, IAgentLogger? log = null)
    {
        _path = string.IsNullOrWhiteSpace(path) ? throw new ArgumentException("Path is required.", nameof(path)) : path;
        _log = log ?? NullAgentLogger.Instance;
    }

    /// <summary>The store path under the profile's ProgramData directory.</summary>
    public static string DefaultPath()
        => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            AgentInstallIdentity.DataDirName,
            FileName);

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

    /// <summary>The persisted state of <paramref name="agentId"/>; empty when the record belongs to another agent.</summary>
    public AgentSignedState Load(string agentId)
    {
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        lock (_gate)
        {
            EnsureLoaded();
            return _state is not null && string.Equals(_state.AgentId, agentId, StringComparison.Ordinal)
                ? _state
                : AgentSignedState.Empty(agentId);
        }
    }

    /// <summary>Replaces the whole record (temp file, flush, atomic replace). On failure nothing changes.</summary>
    public bool TrySave(AgentSignedState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentException.ThrowIfNullOrEmpty(state.AgentId);
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

    /// <summary>A signed revoke was applied for <paramref name="agentId"/>; only ping and agent_state run until it completes.</summary>
    public void MarkRevokePending(string agentId)
    {
        ArgumentException.ThrowIfNullOrEmpty(agentId);
        lock (_gate)
            _revokePendingAgentId = agentId;
    }

    private bool IsQuarantinedLocked(string agentId)
        => string.Equals(_revokePendingAgentId, agentId, StringComparison.Ordinal)
           || (_state is { QuarantineActive: true } state && string.Equals(state.AgentId, agentId, StringComparison.Ordinal));

    private void EnsureLoaded()
    {
        if (_loaded)
            return;
        _loaded = true;
        if (!File.Exists(_path))
            return;

        if (TryRead(out var state))
        {
            _state = state;
            return;
        }

        _unreadable = true;
        var corruptPath = $"{_path}.corrupt-{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}";
        try
        {
            File.Move(_path, corruptPath, overwrite: true);
            _log.Warn($"Signed agent state was unreadable; moved to {Path.GetFileName(corruptPath)}; quarantined until the next signed state.");
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
                || loaded.RegistrationState is not (null or "pending_claim" or "claimed"))
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
            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new StoreFile(Schema, state), JsonOpts);
            using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, _path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
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
