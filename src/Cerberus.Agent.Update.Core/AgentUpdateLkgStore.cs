using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

internal sealed record AgentUpdateLkgRecord(string Schema, string Version, Guid ProductCode, string MsiSha256,
    long MsiLength, string ManifestDigest, long ManifestSequence, string SignerKeyIdentity, string ServiceExeSha256,
    string UpdaterSha256, string WatchedAttemptId, DateTimeOffset PromotedUtc);

internal sealed record AgentUpdateLkgHostRecord(string Schema, string UpdaterVersion, string UpdaterSha256,
    string PlacedBy, DateTimeOffset PlacedUtc, string? AttemptId, string? LkgVersion);

internal sealed record AgentUpdateLkgPromotion(string AttemptId, string NewVersion, string MsiSha256,
    string OldUpdaterSha256, string NewUpdaterSha256, string ManifestDigest, string StageDir);

public sealed class AgentUpdateLkgStore(string updatesRoot)
{
    internal const string DirectoryName = "lkg";
    internal const string UpdaterFileName = "Cerberus.Agent.Updater.exe";
    internal const string Schema = "agent.update.lkg.v1";
    internal const string HostSchema = "agent.update.lkg_host.v1";
    internal const string PromotionFileName = "promote.json";
    internal const string LockFileName = "host.lock";
    internal static JsonSerializerOptions RecordJson { get; } = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
    };

    internal string UpdatesRoot { get; } = AgentUpdateSecurity.NormalizeRoot(updatesRoot);
    internal string Root => Path.Combine(UpdatesRoot, DirectoryName);
    internal string HostPath => Path.Combine(Root, UpdaterFileName);
    internal string HostRecordPath => Path.Combine(Root, "host.json");
    internal string RecordPath => Path.Combine(Root, "lkg.json");
    internal string MsiPath => Path.Combine(Root, AgentUpdateSecurity.ArtifactFileName);
    internal string ManifestPath => Path.Combine(Root, AgentUpdateSecurity.ManifestFileName);

    internal void EnsureRoot() => AgentUpdateSecurity.EnsureProtectedRoot(Root);

    internal AgentUpdateLkgRecord Validate(string? replacedVersion, IReadOnlyList<string> compiledManifestKeys,
        string channel, string? compiledSignerPins, bool allowUnsignedDevBuild)
    {
        var lkg = ReadRecord<AgentUpdateLkgRecord>(RecordPath) ?? throw InvalidLkg();
        AgentUpdateSecurity.ValidateProtectedPath(ManifestPath, UpdatesRoot, allowMissing: false);
        AgentUpdateSecurity.ValidateProtectedPath(MsiPath, UpdatesRoot, allowMissing: false);
        var manifest = AgentUpdateManifestValidator.VerifyStoredSignature(Encoding.UTF8.GetString(ReadSmallFile(ManifestPath)), compiledManifestKeys);
        using var msi = new FileStream(MsiPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        ValidateRelease(lkg, manifest, replacedVersion, AgentUpdateRollbackFloor.Read(UpdatesRoot), msi.Length, Hash(msi));
        AgentUpdateAuthenticode.Verify(MsiPath, channel, compiledSignerPins, allowUnsignedDevBuild);
        return lkg;
    }

    internal static void ValidateRelease(AgentUpdateLkgRecord lkg, AgentUpdateManifest manifest, string? replacedVersion,
        AgentUpdateRollbackFloorRecord? floor, long msiLength, string msiHash)
    {
        if (!ValidRecord(lkg) || !string.Equals(lkg.Version, replacedVersion, StringComparison.Ordinal) ||
            !string.Equals(manifest.Version, lkg.Version, StringComparison.Ordinal) ||
            manifest.ArtifactLength != lkg.MsiLength || msiLength != lkg.MsiLength ||
            !SameHash(lkg.MsiSha256, manifest.Sha256) || !SameHash(lkg.MsiSha256, msiHash) ||
            !SameHash(lkg.ManifestDigest, AgentUpdateManifestValidator.Digest(manifest)) ||
            lkg.ManifestSequence != manifest.Sequence || lkg.SignerKeyIdentity != manifest.EffectiveSignerKeyIdentity ||
            floor is null || AgentVersionComparer.CompareReleaseCore(lkg.Version, floor.MinVersion) is not >= 0)
            throw InvalidLkg();
    }

    internal bool PurgeBelowFloor(AgentUpdateRollbackFloorRecord floor)
    {
        var lkg = ReadRecord<AgentUpdateLkgRecord>(RecordPath);
        if (lkg is null) return false;
        if (!ValidRecord(lkg)) throw InvalidLkg();
        if (AgentVersionComparer.CompareReleaseCore(lkg.Version, floor.MinVersion) is not < 0) return false;
        foreach (var path in new[] { RecordPath, MsiPath, ManifestPath })
            AgentUpdateSecurity.ValidateTrustedPath(path, UpdatesRoot, allowMissing: true);
        // Keep the metadata until both payload deletes succeed so a later tick can complete a partial purge.
        File.Delete(MsiPath);
        File.Delete(ManifestPath);
        File.Delete(RecordPath);
        return true;
    }

    /// <summary>Copies a verified installed updater for a future host registration. The caller holds the host lock.</summary>
    public bool Bootstrap(string installedUpdater, string version, string expectedUpdaterSha256,
        string channel, string? compiledSignerPins, bool allowUnsignedDevBuild, DateTimeOffset now)
    {
        EnsureRoot();
        return BootstrapCore(installedUpdater, version, expectedUpdaterSha256, now,
            () => AgentUpdateSecurity.ValidateInstalledServiceSource(installedUpdater, Path.GetDirectoryName(installedUpdater)!),
            path => AgentUpdateAuthenticode.Verify(path, channel, compiledSignerPins, allowUnsignedDevBuild));
    }

    internal bool BootstrapCore(string installedUpdater, string version, string expectedUpdaterSha256, DateTimeOffset now,
        Action validateInstalledSource, Action<string> verifyAuthenticode)
    {
        if (!AgentUpdateManifestValidator.IsReleaseVersion(version) || !AgentUpdateManifestValidator.IsSha256(expectedUpdaterSha256))
            throw new InvalidOperationException("Installed updater identity is invalid.");
        var previous = ReadHostForRepair();
        bool IsCurrentHostValid()
        {
            if (previous is null || !File.Exists(HostPath)) return false;
            try
            {
                using var host = File.OpenRead(HostPath);
                if (!SameHash(Hash(host), previous.UpdaterSha256)) return false;
                verifyAuthenticode(HostPath);
                return true;
            }
            catch (Exception ex) when (AgentUpdateRollbackGrant.IsStorageFailure(ex)) { return false; }
        }

        if (IsCurrentHostValid()) return false;
        validateInstalledSource();
        var path = Path.Combine(Root, ".stage-" + Guid.NewGuid().ToString("N"));
        var repair = previous is not null || File.Exists(HostPath) || File.Exists(HostRecordPath);
        try
        {
            using (var input = File.OpenRead(installedUpdater))
            using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            {
                input.CopyTo(output);
                output.Flush(flushToDisk: true);
            }
            using (var copied = File.OpenRead(path))
                if (!SameHash(Hash(copied), expectedUpdaterSha256))
                    throw new InvalidOperationException("Installed updater checksum mismatch.");
            verifyAuthenticode(path);
            File.Move(path, HostPath, overwrite: true);
            WriteRecord(HostRecordPath, UpdatesRoot, new AgentUpdateLkgHostRecord(HostSchema, version, expectedUpdaterSha256,
                repair ? "bootstrap_repair" : "bootstrap", now, null, previous?.LkgVersion));
            return true;
        }
        finally { File.Delete(path); }
    }

    internal AgentUpdateLkgHostRecord? ReadHost()
    {
        var host = ReadRecord<AgentUpdateLkgHostRecord>(HostRecordPath);
        if (host is not null && (host.Schema != HostSchema || !AgentUpdateManifestValidator.IsReleaseVersion(host.UpdaterVersion) ||
            !AgentUpdateManifestValidator.IsSha256(host.UpdaterSha256) || host.PlacedBy is not ("bootstrap" or "bootstrap_repair" or "promotion") ||
            host.PlacedUtc == default || host.PlacedUtc.Offset != TimeSpan.Zero ||
            (host.AttemptId is not null && !AgentUpdateSecurity.IsSafeAttemptId(host.AttemptId)) ||
            (host.LkgVersion is not null && !AgentUpdateManifestValidator.IsReleaseVersion(host.LkgVersion))))
            throw new InvalidOperationException("LKG host metadata is invalid.");
        return host;
    }

    private AgentUpdateLkgHostRecord? ReadHostForRepair()
    {
        AgentUpdateSecurity.ValidateTrustedPath(HostRecordPath, UpdatesRoot, allowMissing: true);
        try { return ReadHost(); }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException) { return null; }
    }

    internal AgentUpdateLkgPromotion? ReadPromotion()
    {
        var promotion = ReadRecord<AgentUpdateLkgPromotion>(Path.Combine(Root, PromotionFileName));
        if (promotion is not null) ValidatePromotion(promotion);
        return promotion;
    }

    internal void WritePromotion(AgentUpdateLkgPromotion promotion)
    {
        ValidatePromotion(promotion);
        WriteRecord(Path.Combine(Root, PromotionFileName), UpdatesRoot, promotion);
    }

    private static void ValidatePromotion(AgentUpdateLkgPromotion value)
    {
        if (!AgentUpdateSecurity.IsSafeAttemptId(value.AttemptId) || value.StageDir != "stage-" + value.AttemptId ||
            !AgentUpdateManifestValidator.IsReleaseVersion(value.NewVersion) || !AgentUpdateManifestValidator.IsSha256(value.MsiSha256) ||
            !AgentUpdateManifestValidator.IsSha256(value.OldUpdaterSha256) || !AgentUpdateManifestValidator.IsSha256(value.NewUpdaterSha256) ||
            !AgentUpdateManifestValidator.IsSha256(value.ManifestDigest))
            throw new InvalidOperationException("LKG promotion metadata is invalid.");
    }

    private T? ReadRecord<T>(string path) where T : class
    {
        AgentUpdateSecurity.ValidateTrustedPath(path, UpdatesRoot, allowMissing: true);
        try
        {
            return JsonSerializer.Deserialize<T>(ReadSmallFile(path), RecordJson)
                ?? throw new InvalidOperationException("LKG metadata is empty.");
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    internal static byte[] ReadSmallFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is <= 0 or > AgentUpdateDurableFile.MaxBytes)
            throw new InvalidOperationException("Update record length is invalid.");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    internal static void WriteRecord<T>(string path, string updatesRoot, T value)
    {
        AgentUpdateDurableFile.Write(path, updatesRoot, JsonSerializer.SerializeToElement(value, RecordJson));
    }

    private static bool ValidRecord(AgentUpdateLkgRecord lkg)
        => lkg.Schema == Schema && AgentUpdateManifestValidator.IsReleaseVersion(lkg.Version) && lkg.ProductCode != Guid.Empty &&
           AgentUpdateManifestValidator.IsSha256(lkg.MsiSha256) && lkg.MsiLength > 0 &&
           AgentUpdateManifestValidator.IsSha256(lkg.ManifestDigest) && lkg.ManifestSequence > 0 &&
           !string.IsNullOrWhiteSpace(lkg.SignerKeyIdentity) && AgentUpdateManifestValidator.IsSha256(lkg.ServiceExeSha256) &&
           AgentUpdateManifestValidator.IsSha256(lkg.UpdaterSha256) && AgentUpdateSecurity.IsSafeAttemptId(lkg.WatchedAttemptId) &&
           lkg.PromotedUtc != default && lkg.PromotedUtc.Offset == TimeSpan.Zero;

    private static InvalidOperationException InvalidLkg() => new("Last known good update is invalid or ineligible.");
    private static string Hash(Stream stream) => Convert.ToHexStringLower(SHA256.HashData(stream));
    private static bool SameHash(string left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
