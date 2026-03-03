using System.Text.Json;

namespace Cerberus.Agent.Core;

public sealed class IdempotencyCache
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly string _path;
    private readonly int _maxEntries;
    private readonly TimeSpan _ttl;
    private readonly Dictionary<string, CacheEntry> _entries = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public IdempotencyCache(string path, int maxEntries, TimeSpan ttl)
    {
        _path = path;
        _maxEntries = Math.Max(10, maxEntries);
        _ttl = ttl;
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        LoadBestEffort();
    }

    public bool TryGet(string idempotencyKey, out CommandResult result)
    {
        lock (_gate)
        {
            PruneLocked();
            if (_entries.TryGetValue(idempotencyKey, out var entry) && entry.ExpiresAt > DateTimeOffset.UtcNow)
            {
                result = entry.Result;
                return true;
            }
        }

        result = default!;
        return false;
    }

    public void Set(string idempotencyKey, CommandResult result)
    {
        lock (_gate)
        {
            PruneLocked();
            _entries[idempotencyKey] = new CacheEntry(DateTimeOffset.UtcNow.Add(_ttl), result);
            if (_entries.Count > _maxEntries)
            {
                // Drop oldest by expiry.
                var oldest = _entries.OrderBy(kv => kv.Value.ExpiresAt).First();
                _entries.Remove(oldest.Key);
            }
            PersistBestEffortLocked();
        }
    }

    private void PruneLocked()
    {
        var now = DateTimeOffset.UtcNow;
        var expired = _entries.Where(kv => kv.Value.ExpiresAt <= now).Select(kv => kv.Key).ToList();
        foreach (var k in expired)
            _entries.Remove(k);
    }

    private void LoadBestEffort()
    {
        try
        {
            if (!File.Exists(_path))
                return;
            var raw = File.ReadAllText(_path);
            var data = JsonSerializer.Deserialize<Dictionary<string, CacheEntry>>(raw, JsonOpts);
            if (data is null)
                return;
            lock (_gate)
            {
                _entries.Clear();
                foreach (var kv in data)
                    _entries[kv.Key] = kv.Value;
                PruneLocked();
            }
        }
        catch
        {
            // Ignore corruption; cache is best-effort.
        }
    }

    private void PersistBestEffortLocked()
    {
        try
        {
            var raw = JsonSerializer.Serialize(_entries, JsonOpts);
            File.WriteAllText(_path, raw);
        }
        catch
        {
            // Best-effort.
        }
    }

    private sealed record CacheEntry(DateTimeOffset ExpiresAt, CommandResult Result);
}

