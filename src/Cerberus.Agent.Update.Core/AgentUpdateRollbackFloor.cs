namespace Cerberus.Agent.Core;

internal sealed record AgentUpdateRollbackFloorRecord(string Schema, string MinVersion, string Source,
    long Sequence, string ManifestDigest, DateTimeOffset UpdatedUtc);

/// <summary>Durable monotonic floor. The host serializes writes with its host lock.</summary>
internal static class AgentUpdateRollbackFloor
{
    public const string Schema = "agent.update.rollback_floor.v1";
    public const string FileName = "rollback-floor.json";

    public static AgentUpdateRollbackFloorRecord? Read(string root)
    {
        var path = Path.Combine(root, FileName);
        AgentUpdateSecurity.ValidateTrustedPath(path, root, allowMissing: true);
        byte[] bytes;
        try { bytes = AgentUpdateLkgStore.ReadSmallFile(path); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        var value = System.Text.Json.JsonSerializer.Deserialize<AgentUpdateRollbackFloorRecord>(bytes, AgentUpdateLkgStore.RecordJson);
        return Validate(value);
    }

    public static bool Raise(string root, string minVersion, string source, long sequence, string manifestDigest, DateTimeOffset now)
    {
        var next = Validate(new(Schema, minVersion, source, sequence, manifestDigest, now));
        var current = Read(root);
        if (current is not null && AgentVersionComparer.CompareReleaseCore(next.MinVersion, current.MinVersion) <= 0)
            return false;
        AgentUpdateLkgStore.WriteRecord(Path.Combine(root, FileName), root, next);
        return true;
    }

    public static bool ApplySignedManifest(string root, string installedVersion, string planVersion, string manifestJson,
        IReadOnlyList<string> compiledManifestKeys, DateTimeOffset now)
    {
        if (!string.Equals(installedVersion, planVersion, StringComparison.Ordinal))
            throw new InvalidOperationException("Installed version does not match the update plan.");
        var manifest = AgentUpdateManifestValidator.VerifyStoredSignature(manifestJson, compiledManifestKeys);
        if (!string.Equals(manifest.Version, installedVersion, StringComparison.Ordinal))
            throw new InvalidOperationException("Stored update manifest does not match the installed version.");
        var digest = AgentUpdateManifestValidator.Digest(manifest);
        if (manifest.MinRollbackVersion is not { } minimum || Read(root)?.ManifestDigest == digest)
            return false;
        return Raise(root, minimum, "signed_manifest", manifest.Sequence, digest, now);
    }

    private static AgentUpdateRollbackFloorRecord Validate(AgentUpdateRollbackFloorRecord? value)
    {
        if (value is null || value.Schema != Schema || !AgentUpdateManifestValidator.IsReleaseVersion(value.MinVersion) ||
            value.Source is not ("watch_pass" or "signed_manifest") || value.Sequence <= 0 ||
            !AgentUpdateManifestValidator.IsSha256(value.ManifestDigest) || value.UpdatedUtc == default ||
            value.UpdatedUtc.Offset != TimeSpan.Zero)
            throw new InvalidOperationException("Rollback floor is invalid.");
        return value;
    }
}
