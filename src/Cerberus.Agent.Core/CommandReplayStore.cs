using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

/// <summary>Durable states of an envelope record.</summary>
public static class EnvelopeRecordStates
{
    public const string Reserved = "reserved";
    public const string Started = "started";
    public const string Done = "done";
    public const string RejectedAfterReserve = "rejected_after_reserve";

    internal static bool IsKnown(string? state)
        => state is Reserved or Started or Done or RejectedAfterReserve;
}

/// <summary>One reserved envelope. Every lookup is scoped to <see cref="AgentId"/>.</summary>
public sealed record CommandReplayRecord(
    [property: JsonPropertyName("agent_id")] string AgentId,
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("envelope_sha256")] string EnvelopeSha256,
    [property: JsonPropertyName("nonce")] string Nonce,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("issued_at")] long IssuedAt,
    [property: JsonPropertyName("expires_at")] long ExpiresAt,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("result_b64")] string? ResultB64,
    [property: JsonPropertyName("result_sha256")] string? ResultSha256,
    [property: JsonPropertyName("result_submitted")] bool ResultSubmitted,
    [property: JsonPropertyName("reject_reason"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RejectReason = null)
{
    /// <summary>A result is held and has not reached a final outcome at the server yet.</summary>
    [JsonIgnore]
    public bool HasPendingResult => State == EnvelopeRecordStates.Started
                                    || (State == EnvelopeRecordStates.Done && !ResultSubmitted && ResultB64 is not null);
}

public enum ReplayReserveOutcome
{
    Reserved,
    Full,
    Unavailable,
}

/// <summary>
/// Replay store for signed command envelopes: <c>&lt;DataDir&gt;\Privileged\command-envelopes.v1.json</c>,
/// written as temp file, flushed to disk, then atomically replaced. A corrupt or unreadable
/// file is renamed <c>*.corrupt-&lt;unix&gt;</c> and a new store starts with <c>reset_at = now</c>.
/// On a machine path (see <see cref="ProtectedMachineFile"/>) a file with an untrusted owner or DACL, a
/// directory or a reparse point at the path is not parsed or renamed (a moved file would keep its DACL
/// inside <c>Privileged</c>); the store resets the same way and its first write replaces the object.
/// An untrusted directory chain makes the store unavailable.
/// When the file cannot be written the store is unavailable and reservations fail closed.
/// A write never produces a file the reader rejects: unsubmitted result bytes are bounded by
/// <see cref="MaxUnsubmittedResultBytes"/> at reservation, and a serialization above the read cap fails like a failed write.
/// </summary>
public sealed class CommandReplayStore
{
    public const string FileName = "command-envelopes.v1.json";
    public const int MaxRecords = 1024;
    public const long RetentionSeconds = 24 * 60 * 60;
    public const long MaxHeldResultBytes = 4L * 1024 * 1024;
    /// <summary>
    /// Budget for result bytes held unsubmitted plus one maximal result for every in-flight (reserved or started,
    /// no result yet) record and for the envelope being reserved. Worst case on disk (base64, no JSON escaping):
    /// 1024 records at 1 KiB + 4 MiB submitted cap * 4/3 + this budget * 4/3 = 14.4 MiB, under <see cref="MaxFileBytes"/>.
    /// </summary>
    public const long MaxUnsubmittedResultBytes = 6L * 1024 * 1024;
    internal const long MaxFileBytes = 16L * 1024 * 1024;
    private const string Schema = "cerberus.command-envelopes.v1";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly object _gate = new();
    private readonly string _path;
    private readonly ProtectedMachineFile _file;
    private readonly TimeProvider _time;
    private readonly IAgentLogger _log;
    private List<CommandReplayRecord> _records = new();
    private long _resetAt;
    private bool _loaded;
    private bool _persistPending;
    private bool _untrustedDirectoryLogged;

    /// <param name="enforceFileProvenance">Also demands a SYSTEM/Administrators owner and a DACL without untrusted
    /// writers on a path outside <c>Privileged</c> (always on inside it).</param>
    public CommandReplayStore(string path, TimeProvider? time = null, IAgentLogger? log = null, bool enforceFileProvenance = false)
    {
        _path = string.IsNullOrWhiteSpace(path) ? throw new ArgumentException("Path is required.", nameof(path)) : path;
        _file = new ProtectedMachineFile(_path, enforceFileProvenance);
        _time = time ?? TimeProvider.System;
        _log = log ?? NullAgentLogger.Instance;
    }

    /// <summary>The store path under <c>&lt;DataDir&gt;\Privileged</c>.</summary>
    public static string DefaultPath() => ProtectedMachineFile.DefaultPath(FileName);

    /// <summary>Envelopes issued before this Unix time are rejected (step 15). 0 for a store that never existed.</summary>
    public long ResetAt
    {
        get
        {
            lock (_gate)
            {
                EnsureLoaded();
                return _resetAt;
            }
        }
    }

    public bool IsAvailable
    {
        get
        {
            lock (_gate)
                return EnsureLoaded() && !_persistPending;
        }
    }

    /// <summary>Step 13: the record with this id among records of <paramref name="agentId"/>.</summary>
    public CommandReplayRecord? Find(string agentId, string id)
    {
        lock (_gate)
        {
            EnsureLoaded();
            return _records.FirstOrDefault(r => Same(r, agentId, id));
        }
    }

    /// <summary>Step 16: the nonce is held by another retained record of <paramref name="agentId"/>.</summary>
    public bool IsNonceUsed(string agentId, string nonce, string exceptId)
    {
        lock (_gate)
        {
            EnsureLoaded();
            return _records.Any(r => string.Equals(r.AgentId, agentId, StringComparison.Ordinal)
                                     && string.Equals(r.Nonce, nonce, StringComparison.Ordinal)
                                     && !string.Equals(r.Id, exceptId, StringComparison.Ordinal));
        }
    }

    /// <summary>All retained records of <paramref name="agentId"/>, oldest expiry first.</summary>
    public IReadOnlyList<CommandReplayRecord> Records(string agentId)
    {
        lock (_gate)
        {
            EnsureLoaded();
            return _records.Where(r => string.Equals(r.AgentId, agentId, StringComparison.Ordinal))
                .OrderBy(r => r.ExpiresAt).ThenBy(r => r.Id, StringComparer.Ordinal).ToList();
        }
    }

    /// <summary>Step 18: the durable reservation. Live records are never evicted to make room.</summary>
    public ReplayReserveOutcome TryReserve(CommandReplayRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        lock (_gate)
        {
            if (!EnsureLoaded() || _records.Any(r => Same(r, record.AgentId, record.Id)))
                return ReplayReserveOutcome.Unavailable;

            var now = NowUnix();
            var next = Purge(_records, now);
            if (next.Count >= MaxRecords)
            {
                var evictable = next.Where(r => IsEvictable(r, now))
                    .OrderBy(r => r.ExpiresAt).ThenBy(r => r.Id, StringComparer.Ordinal)
                    .Take(next.Count - MaxRecords + 1).ToHashSet();
                next = next.Where(r => !evictable.Contains(r)).ToList();
                if (next.Count >= MaxRecords)
                    return ReplayReserveOutcome.Full;
            }

            var unsubmitted = next.Where(r => !r.ResultSubmitted).Sum(r => ExposureBytes(r, now));
            if (unsubmitted + EnvelopeExecutionQueue.MaxResultBodyBytes > MaxUnsubmittedResultBytes)
                return ReplayReserveOutcome.Full;

            next.Add(record with { State = EnvelopeRecordStates.Reserved });
            return Commit(next) ? ReplayReserveOutcome.Reserved : ReplayReserveOutcome.Unavailable;
        }
    }

    /// <summary>
    /// Replaces the record with the same agent id and id and persists it. On a write failure
    /// the store keeps its previous content and returns false.
    /// </summary>
    public bool TryUpdate(CommandReplayRecord updated)
    {
        ArgumentNullException.ThrowIfNull(updated);
        lock (_gate)
        {
            if (!EnsureLoaded())
                return false;
            var index = _records.FindIndex(r => Same(r, updated.AgentId, updated.Id));
            if (index < 0)
                return false;

            var next = _records.ToList();
            next[index] = updated;
            return Commit(CapHeldResults(Purge(next, NowUnix())));
        }
    }

    private bool Commit(List<CommandReplayRecord> next)
    {
        if (!TryPersist(next, _resetAt))
            return false;
        _records = next;
        _persistPending = false;
        return true;
    }

    private bool EnsureLoaded()
    {
        if (_loaded)
        {
            if (_persistPending && TryPersist(_records, _resetAt))
                _persistPending = false;
            return true;
        }

        try
        {
            _file.ValidateDirectory();
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex))
        {
            if (!_untrustedDirectoryLogged)
                _log.Error($"Command replay store directory is untrusted ({ex.GetType().Name}); the store is unavailable.");
            _untrustedDirectoryLogged = true;
            return false;
        }

        _untrustedDirectoryLogged = false;
        if (!_file.Exists())
        {
            _records = new List<CommandReplayRecord>();
            _resetAt = 0;
            _loaded = true;
            return true;
        }

        try
        {
            _file.ValidateFile();
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex))
        {
            var resetNow = NowUnix();
            _log.Warn($"Command replay store failed provenance ({ex.GetType().Name}); reset at {resetNow}.");
            _records = new List<CommandReplayRecord>();
            _resetAt = resetNow;
            _loaded = true;
            _persistPending = !TryPersist(_records, _resetAt);
            return true;
        }

        if (TryRead(out var records, out var resetAt))
        {
            _records = Purge(records, NowUnix());
            _resetAt = resetAt;
            _loaded = true;
            return true;
        }

        var now = NowUnix();
        var corruptPath = $"{_path}.corrupt-{now}";
        try
        {
            File.Move(_path, corruptPath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Error($"Command replay store unreadable and could not be set aside: {ex.GetType().Name}.");
            return false;
        }

        _log.Warn($"Command replay store was corrupt; moved to {Path.GetFileName(corruptPath)} and reset at {now}.");
        _records = new List<CommandReplayRecord>();
        _resetAt = now;
        _loaded = true;
        _persistPending = !TryPersist(_records, _resetAt);
        return true;
    }

    private bool TryRead(out List<CommandReplayRecord> records, out long resetAt)
    {
        records = new List<CommandReplayRecord>();
        resetAt = 0;
        try
        {
            var info = new FileInfo(_path);
            if (info.Length > MaxFileBytes)
                return false;
            var file = JsonSerializer.Deserialize<StoreFile>(File.ReadAllBytes(_path), JsonOpts);
            if (file is null || file.Schema != Schema || file.ResetAt < 0 || file.Records is null
                || file.Records.Any(r => !IsValid(r)))
                return false;
            records = file.Records.ToList();
            resetAt = file.ResetAt;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return false;
        }
    }

    private bool TryPersist(List<CommandReplayRecord> records, long resetAt)
    {
        var tempPath = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            _file.EnsureDirectory();
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new StoreFile(Schema, resetAt, records), JsonOpts);
            if (bytes.LongLength > MaxFileBytes)
            {
                _log.Error("Command replay store write refused: the serialized store exceeds the read cap.");
                return false;
            }

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
            _log.Error($"Command replay store write failed: {ex.GetType().Name}.");
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

    /// <summary>A record ends its retention at <c>expires_at + 24 h</c>; the outbox stops then too.</summary>
    private static List<CommandReplayRecord> Purge(IEnumerable<CommandReplayRecord> records, long now)
        => records.Where(r => now <= r.ExpiresAt + RetentionSeconds).ToList();

    /// <summary>Only records past their window and without a pending result may make room.</summary>
    private static bool IsEvictable(CommandReplayRecord record, long now)
        => now > record.ExpiresAt + CommandEnvelopeVerifier.SkewSeconds && !record.HasPendingResult;

    /// <summary>Above 4 MiB of held result bytes, the oldest submitted results drop their bytes.</summary>
    private static List<CommandReplayRecord> CapHeldResults(List<CommandReplayRecord> records)
    {
        long held = records.Sum(r => HeldBytes(r));
        if (held <= MaxHeldResultBytes)
            return records;

        var drop = records.Where(r => r.ResultSubmitted && r.ResultB64 is not null)
            .OrderBy(r => r.ExpiresAt).ThenBy(r => r.Id, StringComparer.Ordinal).ToList();
        var dropped = new HashSet<CommandReplayRecord>();
        foreach (var record in drop)
        {
            if (held <= MaxHeldResultBytes)
                break;
            held -= HeldBytes(record);
            dropped.Add(record);
        }

        return records.Select(r => dropped.Contains(r) ? r with { ResultB64 = null } : r).ToList();
    }

    private static long HeldBytes(CommandReplayRecord record)
        => record.ResultB64 is null ? 0 : record.ResultB64.Length / 4L * 3L;

    /// <summary>
    /// Held result bytes, or one maximal result for a started record, or a reserved record still inside its window,
    /// that has none yet. A reserved record past its window never runs (the queue re-checks it), so it does not count.
    /// </summary>
    private static long ExposureBytes(CommandReplayRecord record, long now)
        => record.ResultB64 is not null ? HeldBytes(record)
            : record.State == EnvelopeRecordStates.Started
              || (record.State == EnvelopeRecordStates.Reserved && now <= record.ExpiresAt + CommandEnvelopeVerifier.SkewSeconds)
                ? EnvelopeExecutionQueue.MaxResultBodyBytes
                : 0;

    private static bool IsValid(CommandReplayRecord? r)
        => r is not null
           && !string.IsNullOrEmpty(r.AgentId) && !string.IsNullOrEmpty(r.Id) && !string.IsNullOrEmpty(r.Nonce)
           && !string.IsNullOrEmpty(r.Type) && r.EnvelopeSha256 is { Length: 64 }
           && EnvelopeRecordStates.IsKnown(r.State) && r.IssuedAt > 0 && r.ExpiresAt > r.IssuedAt
           && (r.ResultSha256 is null || r.ResultSha256.Length == 64);

    private static bool Same(CommandReplayRecord record, string agentId, string id)
        => string.Equals(record.AgentId, agentId, StringComparison.Ordinal)
           && string.Equals(record.Id, id, StringComparison.Ordinal);

    private long NowUnix() => _time.GetUtcNow().ToUnixTimeSeconds();

    private sealed record StoreFile(
        [property: JsonPropertyName("schema")] string Schema,
        [property: JsonPropertyName("reset_at")] long ResetAt,
        [property: JsonPropertyName("records")] IReadOnlyList<CommandReplayRecord> Records);
}
