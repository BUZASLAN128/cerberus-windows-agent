using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public static class OfflineTelemetryKinds
{
    public const string Snapshot = "snapshot";
    public const string Events = "events";
    public const string ProbeResult = "probe_result";
}

public sealed record OfflineTelemetryRecord(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("json")] string Json,
    [property: JsonPropertyName("created_at_utc")] DateTimeOffset CreatedAtUtc,
    [property: JsonPropertyName("idempotency_key")] string? IdempotencyKey,
    [property: JsonPropertyName("priority")] int Priority);

internal sealed record OfflineTelemetryStoreEnvelope(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("checksum_sha256")] string ChecksumSha256,
    [property: JsonPropertyName("records")] IReadOnlyList<OfflineTelemetryRecord> Records);

public sealed class OfflineTelemetryBuffer
{
    private const string StoreSchemaVersion = "cerberus.offline_telemetry_buffer.v1";

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };

    private readonly string _path;
    private readonly int _maxEntries;
    private readonly int _maxBytes;
    private readonly TimeSpan _ttl;

    public OfflineTelemetryBuffer(
        string path,
        int maxEntries = 200,
        int maxBytes = 512 * 1024,
        TimeSpan? ttl = null)
    {
        _path = string.IsNullOrWhiteSpace(path) ? throw new ArgumentException("Offline buffer path is required.", nameof(path)) : path;
        _maxEntries = Math.Max(1, maxEntries);
        _maxBytes = Math.Max(AgentTelemetryLimits.MaxJsonBytes, maxBytes);
        _ttl = ttl ?? TimeSpan.FromHours(24);
    }

    public async Task EnqueueAsync(
        string kind,
        object body,
        string? idempotencyKey,
        int priority,
        CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        var bytes = Encoding.UTF8.GetByteCount(json);
        if (bytes > AgentTelemetryLimits.MaxJsonBytes)
            throw new InvalidOperationException($"Offline telemetry item too large: {bytes} bytes.");

        var records = await LoadAsync(ct).ConfigureAwait(false);
        records = PruneExpired(records, DateTimeOffset.UtcNow);

        if (!string.IsNullOrWhiteSpace(idempotencyKey))
            records.RemoveAll(r => string.Equals(r.IdempotencyKey, idempotencyKey, StringComparison.Ordinal));

        if (string.Equals(kind, OfflineTelemetryKinds.Snapshot, StringComparison.Ordinal))
            records.RemoveAll(r => string.Equals(r.Kind, OfflineTelemetryKinds.Snapshot, StringComparison.Ordinal));

        records.Add(new OfflineTelemetryRecord(
            Id: Guid.NewGuid().ToString("N"),
            Kind: kind,
            Json: json,
            CreatedAtUtc: DateTimeOffset.UtcNow,
            IdempotencyKey: string.IsNullOrWhiteSpace(idempotencyKey) ? null : idempotencyKey,
            Priority: priority));

        records = PruneToLimits(records);
        await SaveAsync(records, ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<OfflineTelemetryRecord>> ReadBatchAsync(int maxItems, CancellationToken ct)
    {
        var records = PruneExpired(await LoadAsync(ct).ConfigureAwait(false), DateTimeOffset.UtcNow);
        records = records
            .OrderBy(r => r.CreatedAtUtc)
            .Take(Math.Max(1, maxItems))
            .ToList();
        return records;
    }

    public async Task RemoveAsync(IEnumerable<string> ids, CancellationToken ct)
    {
        var remove = ids.ToHashSet(StringComparer.Ordinal);
        if (remove.Count == 0)
            return;

        var records = await LoadAsync(ct).ConfigureAwait(false);
        records.RemoveAll(r => remove.Contains(r.Id));
        await SaveAsync(records, ct).ConfigureAwait(false);
    }

    private async Task<List<OfflineTelemetryRecord>> LoadAsync(CancellationToken ct)
    {
        if (!File.Exists(_path))
            return new List<OfflineTelemetryRecord>();

        try
        {
            var json = await File.ReadAllTextAsync(_path, ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(json))
                return new List<OfflineTelemetryRecord>();

            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                return JsonSerializer.Deserialize<List<OfflineTelemetryRecord>>(json, JsonOpts)
                    ?? new List<OfflineTelemetryRecord>();
            }

            var envelope = JsonSerializer.Deserialize<OfflineTelemetryStoreEnvelope>(json, JsonOpts);
            if (envelope is null || !string.Equals(envelope.SchemaVersion, StoreSchemaVersion, StringComparison.Ordinal))
                throw new InvalidDataException("Unknown offline telemetry buffer schema.");

            var records = envelope.Records.ToList();
            var recordsJson = JsonSerializer.Serialize(records, JsonOpts);
            var checksum = ComputeSha256(recordsJson);
            if (!string.Equals(checksum, envelope.ChecksumSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Offline telemetry buffer checksum mismatch.");

            return records;
        }
        catch (Exception ex) when (ex is JsonException or IOException or InvalidDataException or UnauthorizedAccessException)
        {
            QuarantineCorruptBuffer();
            return new List<OfflineTelemetryRecord>();
        }
    }

    private async Task SaveAsync(IReadOnlyList<OfflineTelemetryRecord> records, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        var normalized = records.ToList();
        var recordsJson = JsonSerializer.Serialize(normalized, JsonOpts);
        var envelope = new OfflineTelemetryStoreEnvelope(
            StoreSchemaVersion,
            ComputeSha256(recordsJson),
            normalized);
        var json = JsonSerializer.Serialize(envelope, JsonOpts);

        var tempPath = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = new FileStream(
                tempPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                var bytes = Encoding.UTF8.GetBytes(json);
                await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
            }

            if (File.Exists(_path))
            {
                File.Replace(tempPath, _path, destinationBackupFileName: null, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tempPath, _path);
            }
        }
        finally
        {
            if (File.Exists(tempPath))
                File.Delete(tempPath);
        }
    }

    private List<OfflineTelemetryRecord> PruneExpired(List<OfflineTelemetryRecord> records, DateTimeOffset now)
    {
        records.RemoveAll(r => now - r.CreatedAtUtc > _ttl);
        return records;
    }

    private List<OfflineTelemetryRecord> PruneToLimits(List<OfflineTelemetryRecord> records)
    {
        while (records.Count > _maxEntries)
            DropLowestPriorityOldest(records);

        while (EstimateStoreBytes(records) > _maxBytes && records.Count > 0)
            DropLowestPriorityOldest(records);

        return records;
    }

    private static int EstimateStoreBytes(IReadOnlyList<OfflineTelemetryRecord> records)
    {
        var json = JsonSerializer.Serialize(records, JsonOpts);
        return Encoding.UTF8.GetByteCount(json);
    }

    private static void DropLowestPriorityOldest(List<OfflineTelemetryRecord> records)
    {
        var drop = records
            .OrderBy(r => r.Priority)
            .ThenBy(r => r.CreatedAtUtc)
            .FirstOrDefault();
        if (drop is not null)
            records.Remove(drop);
    }

    private static string ComputeSha256(string value)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private void QuarantineCorruptBuffer()
    {
        if (!File.Exists(_path))
            return;

        var dir = Path.GetDirectoryName(_path) ?? "";
        var file = Path.GetFileName(_path);
        var quarantinePath = Path.Combine(
            dir,
            $"{file}.corrupt.{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}");
        try
        {
            File.Move(_path, quarantinePath, overwrite: false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            try
            {
                File.Delete(_path);
            }
            catch (Exception deleteEx) when (deleteEx is IOException or UnauthorizedAccessException)
            {
                // The next read will retry quarantine/delete. Do not crash the heartbeat loop on a bad cache file.
            }
        }
    }
}
