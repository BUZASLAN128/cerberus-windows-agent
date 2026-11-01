using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

public static class AgentUpdateSequenceStore
{
    private const string SequenceFileName = "highest-sequence.json";

    /// <summary>Largest accepted distance between a manifest sequence and the current Unix-millisecond clock (24 hours).</summary>
    public const long MaxSequenceLeadMilliseconds = 24L * 60 * 60 * 1000;

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
    public static void Accept(string root, long sequence, string digest, DateTimeOffset? utcNow = null)
    {
        if (sequence <= 0 || digest.Length != 64 || !digest.All(Uri.IsHexDigit))
            throw new InvalidOperationException("Update manifest acceptance is invalid.");
        // Release sequences are Unix milliseconds at signing time; a value far ahead of the clock is not a valid release.
        if (sequence > (utcNow ?? DateTimeOffset.UtcNow).ToUnixTimeMilliseconds() + MaxSequenceLeadMilliseconds)
            throw new InvalidOperationException("Update manifest sequence is out of range.");
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
