using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

internal sealed record AgentUpdateLkgRecord(string Schema, string Version, Guid ProductCode, string MsiSha256,
    long MsiLength, string ManifestDigest, long ManifestSequence, string SignerKeyIdentity, string ServiceExeSha256,
    string UpdaterSha256, string WatchedAttemptId, DateTimeOffset PromotedUtc);

internal sealed record AgentUpdateLkgHostRecord(string Schema, string UpdaterVersion, string UpdaterSha256,
    string PlacedBy, DateTimeOffset PlacedUtc, string? AttemptId, string? LkgVersion)
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LabCampaignId { get; init; }
}

internal sealed record AgentUpdateLkgPromotion(string AttemptId, string NewVersion, string MsiSha256,
    string OldUpdaterSha256, string NewUpdaterSha256, string ManifestDigest, string StageDir)
{
    internal const int MaxRetries = 3;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? PivotStarted { get; init; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? RetryCount { get; init; }
}

public sealed class AgentUpdateLkgStore(string updatesRoot)
{
    internal const string DirectoryName = "lkg";
    internal const string UpdaterFileName = "Cerberus.Agent.Updater.exe";
    internal const string Schema = "agent.update.lkg.v1";
    internal const string HostSchema = "agent.update.lkg_host.v1";
    internal const string PromotionFileName = "promote.json";
    internal const string StalePromotionPrefix = "promote.stale-";
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

    /// <summary>Bootstraps the protected updater host and creates its task while holding the host lock.</summary>
    public void BootstrapWatchHost(string runtimeDirectory, string version, string channel, string? compiledSignerPins,
        DateTimeOffset now, Func<string, string> readUpdaterVersion, string? labCampaignId, Func<string, string, bool>? isAdmittedLabUpdater)
    {
        if (!OperatingSystem.IsWindows() || !AgentBuildProfile.IsServer || !AgentUpdateSecurity.IsLocalSystem() ||
            !string.Equals(UpdatesRoot, AgentUpdateSecurity.DefaultPrivilegedRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("The server update host bootstrap requires LocalSystem.");

        var installedUpdater = Path.Combine(Path.GetFullPath(runtimeDirectory), UpdaterFileName);
        EnsureRoot();
        ValidateStalePromotionLayout();
        var lockPath = Path.Combine(Root, LockFileName);
        AgentUpdateSecurity.ValidateProtectedPath(lockPath, UpdatesRoot, allowMissing: true);
        using var gate = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        BootstrapCore(installedUpdater, version, null, now,
            () => AgentUpdateSecurity.ValidateInstalledServiceSource(installedUpdater, Path.GetDirectoryName(installedUpdater)!),
            path => AgentUpdateAuthenticode.Verify(path, channel, compiledSignerPins, allowUnsignedDevBuild: labCampaignId is not null),
            labCampaignId, isAdmittedLabUpdater, readUpdaterVersion);
        AgentUpdateWatchTask.CreateIfAbsent();
    }

    internal bool BootstrapCore(string installedUpdater, string version, string? expectedUpdaterSha256, DateTimeOffset now,
        Action validateInstalledSource, Action<string> verifyAuthenticode, string? labCampaignId = null,
        Func<string, string, bool>? isAdmittedLabUpdater = null, Func<string, string>? readUpdaterVersion = null)
    {
        if (!AgentUpdateManifestValidator.IsReleaseVersion(version) ||
            (expectedUpdaterSha256 is not null && !AgentUpdateManifestValidator.IsSha256(expectedUpdaterSha256)))
            throw new InvalidOperationException("Installed updater identity is invalid.");

        void VerifyUpdater(string path, string updaterVersion, string sha256)
        {
            if (labCampaignId is not null && isAdmittedLabUpdater?.Invoke(updaterVersion, sha256) != true)
                throw new InvalidOperationException("The updater does not match a completed lab admission.");
            verifyAuthenticode(path);
            // A pending installer rename can leave a different, still correctly signed updater at the source.
            if (readUpdaterVersion is not null &&
                AgentUpdateCampaignTransition.Release(readUpdaterVersion(path)) != AgentUpdateCampaignTransition.Release(updaterVersion))
                throw new InvalidOperationException("The installed updater release does not match its bootstrap identity.");
        }

        var previous = ReadHostForRepair();
        var recordedCampaignMatches = previous is not null && previous.LabCampaignId == labCampaignId;
        // Promotion records without the optional marker are still bound by the exact current campaign receipt.
        var canVerifyPrevious = recordedCampaignMatches ||
            (labCampaignId is not null && previous is { LabCampaignId: null, PlacedBy: "promotion" });
        bool IsCurrentHostValid()
        {
            if (previous is null || !canVerifyPrevious || !File.Exists(HostPath)) return false;
            try
            {
                using var host = File.OpenRead(HostPath);
                if (!SameHash(Hash(host), previous.UpdaterSha256)) return false;
                VerifyUpdater(HostPath, previous.UpdaterVersion, previous.UpdaterSha256);
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
            string sourceHash;
            using (var input = File.OpenRead(installedUpdater))
            using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
            {
                sourceHash = expectedUpdaterSha256 ?? Hash(input);
                input.Position = 0;
                input.CopyTo(output);
                output.Flush(flushToDisk: true);
            }
            using (var copied = File.OpenRead(path))
            {
                if (!SameHash(Hash(copied), sourceHash))
                    throw new InvalidOperationException("Installed updater checksum mismatch.");
                VerifyUpdater(path, version, sourceHash);
            }
            File.Move(path, HostPath, overwrite: true);
            // A markerless promotion cannot carry an LKG version across a repair into a different build class.
            var cachedLkgVersion = recordedCampaignMatches && (labCampaignId is not null || previous?.PlacedBy != "promotion")
                ? previous?.LkgVersion : null;
            WriteRecord(HostRecordPath, UpdatesRoot, new AgentUpdateLkgHostRecord(HostSchema, version, sourceHash,
                repair ? "bootstrap_repair" : "bootstrap", now, null, cachedLkgVersion)
            {
                LabCampaignId = labCampaignId,
            });
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
            !AgentUpdateManifestValidator.IsSha256(value.ManifestDigest) ||
            (value.PivotStarted, value.RetryCount) is not
                ((null, null) or (false, 0) or (true, >= 0 and <= AgentUpdateLkgPromotion.MaxRetries)))
            throw new InvalidOperationException("LKG promotion metadata is invalid.");
    }

    internal void ValidateStalePromotionLayout()
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(Root, "promote.stale*"))
        {
            var name = Path.GetFileName(path);
            if (!name.StartsWith(StalePromotionPrefix, StringComparison.Ordinal) ||
                !name.EndsWith(".json", StringComparison.Ordinal) ||
                name.Length != StalePromotionPrefix.Length + 64 + ".json".Length ||
                name[StalePromotionPrefix.Length..^5].Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
                (File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
                throw new InvalidOperationException("Stale LKG promotion artifact has an invalid layout.");
        }
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
        var record = value switch
        {
            AgentUpdateLkgHostRecord host => JsonSerializer.SerializeToElement(
                host with { PlacedUtc = host.PlacedUtc.ToUniversalTime() }, RecordJson),
            AgentUpdateLkgRecord lkg => JsonSerializer.SerializeToElement(
                lkg with { PromotedUtc = lkg.PromotedUtc.ToUniversalTime() }, RecordJson),
            _ => JsonSerializer.SerializeToElement(value, RecordJson),
        };
        AgentUpdateDurableFile.Write(path, updatesRoot, record);
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
