using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public sealed record AgentEnrollmentRevokeCleanup(long Generation, string Nonce, string AgentId,
    string Product, bool Completed = false);

/// <summary>One protected post-publication obligation; no credential probe or enrollment is retried here.</summary>
public sealed class AgentEnrollmentRevokeCleanupStore(string path)
{
    private readonly ProtectedMachineFile _file = new(path);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, MaxDepth = 4,
    };

    public static AgentEnrollmentRevokeCleanupStore ForProduct(string product)
        => new(AgentSignedStateStore.DefaultPathForProduct(product) + ".enrollment-cleanup");

    public AgentEnrollmentRevokeCleanup? Read()
    {
        _file.ValidateDirectory();
        if (!_file.Exists()) return null;
        _file.ValidateFile();
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is <= 0 or > 4096) throw new InvalidDataException("Invalid enrollment cleanup size.");
        using var document = JsonDocument.Parse(input, new JsonDocumentOptions { MaxDepth = 4 });
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            document.RootElement.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1))
            throw new InvalidDataException("Invalid enrollment cleanup record.");
        var record = document.Deserialize<AgentEnrollmentRevokeCleanup>(Json);
        if (!Valid(record)) throw new InvalidDataException("Invalid enrollment cleanup binding.");
        return record;
    }

    public bool RecordCommitted(AgentEnrollmentRevokeCleanup record)
    {
        if (!Valid(record) || record.Completed) return false;
        var prior = Read();
        if (prior is not null && (prior.Generation > record.Generation ||
            (prior.Generation == record.Generation && prior with { Completed = false } != record)))
            return false;
        if (prior is not null && prior with { Completed = false } == record) return true;
        return Write(record);
    }

    /// <summary>Caller holds the lifecycle generation fence. A different adoption can never consume this obligation.</summary>
    public bool TryComplete(AgentLifecycleSnapshot lifecycle, string agentId, Func<string, bool> clearLegacyRevoke)
    {
        var record = Read();
        if (record is null || record.AgentId != agentId || lifecycle.Generation != record.Generation ||
            lifecycle.LastEnrollmentNonce != record.Nonce || lifecycle.State != AgentLifecycleState.Active ||
            !lifecycle.QuiescenceComplete) return false;
        return record.Completed || (clearLegacyRevoke(record.AgentId) && Write(record with { Completed = true }));
    }

    private static bool Valid(AgentEnrollmentRevokeCleanup? record)
        => record is { Generation: > 0 } && Guid.TryParseExact(record.Nonce, "N", out _) &&
           !string.IsNullOrWhiteSpace(record.AgentId) && record.AgentId.Length <= 256 &&
           record.Product is AgentProducts.Cerberus or AgentProducts.Secondary;

    private bool Write(AgentEnrollmentRevokeCleanup record)
    {
        var temp = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            _file.EnsureDirectory();
            using (var output = _file.CreateTemp(temp))
            {
                output.Write(JsonSerializer.SerializeToUtf8Bytes(record, Json));
                output.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex))
        {
            try { File.Delete(temp); } catch (Exception cleanup) when (ProtectedMachineFile.IsFailure(cleanup)) { }
            return false;
        }
    }
}
