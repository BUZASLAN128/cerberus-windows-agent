using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal sealed partial class LkgPromotion(
    AgentUpdateLkgStore store,
    AgentUpdateBuildMetadata metadata,
    Func<LkgPromotion.RuntimeIdentity?> readRuntimeIdentity,
    Action<string, string, bool> validateProtectedPath,
    Action<string, string> validateInstalledSource,
    Action<string, string> verifyArtifact,
    Func<string, string, bool> probe,
    Action<string> log)
{
    internal sealed record RuntimeIdentity(string Version, Guid ProductCode, string ServiceExeSha256, string RuntimeRoot);

    private const string RetiredPrefix = "retired-";
    private const string PreviousHostSuffix = ".host.json";
    private const string FailedHostSuffix = ".failed.exe";
    private static readonly string[] RetiredSuffixes = [".msi", ".manifest.json", ".lkg.json", PreviousHostSuffix, FailedHostSuffix, ".exe"];
    private readonly IReadOnlyList<string> _manifestKeys = AgentUpdateTrustBuilder.ResolveUpdateManifestPublicKeys(
        metadata.ManifestPublicKeysB64, null, null, null, null);

    /// <summary>Starts promotion of a persisted passed watch. The caller holds lkg\host.lock.</summary>
    internal static bool Run(AgentUpdateLkgStore store, AgentUpdateJournalStore journal, AgentUpdateWatchRecord watch,
        AgentUpdatePlan plan, AgentUpdateBuildMetadata metadata, Func<RuntimeIdentity?> readRuntimeIdentity, Func<string, string, bool> isAdmittedLabArtifact,
        Action<string> log)
        => Create(store, metadata, readRuntimeIdentity, isAdmittedLabArtifact, log).Apply(journal.Read, journal.Change, watch, plan, resume: false);

    /// <summary>Recovers a promotion or finishes cleanup. The caller holds lkg\host.lock.</summary>
    internal static bool Resume(AgentUpdateLkgStore store, AgentUpdateJournalStore journal, AgentUpdateWatchRecord? watch,
        AgentUpdatePlan? plan, AgentUpdateBuildMetadata metadata, Func<RuntimeIdentity?> readRuntimeIdentity, Func<string, string, bool> isAdmittedLabArtifact,
        Action<string> log)
        => Create(store, metadata, readRuntimeIdentity, isAdmittedLabArtifact, log).Apply(journal.Read, journal.Change, watch, plan, resume: true);

    /// <summary>Removes retired files at host start. The caller holds lkg\host.lock.</summary>
    internal static void CleanupRetired(AgentUpdateLkgStore store)
    {
        AgentUpdateSecurity.ValidateProtectedPath(store.Root, store.UpdatesRoot, allowMissing: false);
        if (store.ReadPromotion() is not null) return;
        foreach (var path in Directory.EnumerateFiles(store.Root, RetiredPrefix + "*"))
        {
            var name = Path.GetFileName(path);
            if (!RetiredSuffixes.Any(suffix => name.EndsWith(suffix, StringComparison.Ordinal) &&
                    AgentUpdateSecurity.IsSafeAttemptId(name[RetiredPrefix.Length..^suffix.Length])))
                continue;
            AgentUpdateSecurity.ValidateProtectedPath(path, store.UpdatesRoot, allowMissing: false);
            File.Delete(path);
        }
    }

    private static LkgPromotion Create(AgentUpdateLkgStore store, AgentUpdateBuildMetadata metadata, Func<RuntimeIdentity?> readRuntimeIdentity,
        Func<string, string, bool> isAdmittedLabArtifact, Action<string> log)
    {
        if (!AgentBuildProfile.IsServer || !AgentUpdateSecurity.IsLocalSystem())
            throw new InvalidOperationException("LKG promotion requires the server host running as LocalSystem.");
        return new(store, metadata, readRuntimeIdentity, AgentUpdateSecurity.ValidateProtectedPath,
            AgentUpdateSecurity.ValidateInstalledServiceSource,
            (path, hash) => VerifyAuthenticode(metadata, path, hash, isAdmittedLabArtifact), LkgProbe.Run, log);
    }

    internal static void VerifyAuthenticode(AgentUpdateBuildMetadata metadata, string path, string hash,
        Func<string, string, bool> isAdmittedLabArtifact)
    {
        var admittedUnsigned = UpdaterLab.IsLabBuild && metadata.ReleaseChannel == "dev" && metadata.AllowUnsignedDevBuild &&
            metadata.AllowedSignerKeyIdentity == "unsigned-dev" && isAdmittedLabArtifact(path, hash);
        AgentUpdateAuthenticode.Verify(path, metadata.ReleaseChannel, metadata.AllowedSignerKeyIdentity, admittedUnsigned);
    }

    internal bool Apply(Func<AgentUpdateJournal> readJournal, Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> changeJournal,
        AgentUpdateWatchRecord? watch, AgentUpdatePlan? plan, bool resume)
    {
        Validate(store.Root, allowMissing: false);
        var promotion = store.ReadPromotion();
        if (resume != (promotion is not null)) return false;

        var active = readJournal();
        var activeWatch = watch is not null && plan is not null && active.Phase == AgentUpdateWatchJournal.CommittedWatch &&
            LkgWatchHostBinding.BindsWatch(active, watch.AttemptId);
        if (promotion is not null && !activeWatch)
        {
            try
            {
                if (active.Phase == AgentUpdateStates.Installed && active.AttemptId == promotion.AttemptId &&
                    active.HealthyInstalledVersion == promotion.NewVersion && !IsTerminalFailure(active, promotion.AttemptId) &&
                    IsPublished(promotion, active.HealthyInstalledSequence))
                {
                    Cleanup(promotion);
                    return true;
                }
            }
            catch (Exception ex) when (IsPromotionFailure(ex)) { }
            return Fail(active, changeJournal, promotion, verifiedPlan: null);
        }
        if (!activeWatch || watch is null || plan is null)
            return false;

        var stage = Path.Combine(store.Root, "stage-" + watch.AttemptId);
        var preparedPath = Path.Combine(stage, "lkg.json");
        var runtimeVerified = false;
        var committed = false;
        try
        {
            RequirePassedWatch(watch, plan);
            if (promotion is not null && !MatchesPlan(promotion, plan)) throw InvalidPromotion();
            Validate(preparedPath, allowMissing: true);
            var prepared = promotion is not null && File.Exists(preparedPath);
            var identity = RequireRuntime(watch);
            runtimeVerified = true;
            if (AgentUpdateRollbackFloor.Read(store.UpdatesRoot) is { } floor &&
                AgentVersionComparer.CompareReleaseCore(plan.Version, floor.MinVersion) is not >= 0)
                throw InvalidPromotion();
            if (promotion is null)
            {
                if (Directory.Exists(stage)) throw InvalidPromotion();
                var previousHost = store.ReadHost() ?? throw InvalidPromotion();
                if (!SameHash(HashProtectedFile(store.HostPath), previousHost.UpdaterSha256)) throw InvalidPromotion();
                var installedUpdater = Path.Combine(identity.RuntimeRoot, AgentUpdateLkgStore.UpdaterFileName);
                validateInstalledSource(installedUpdater, identity.RuntimeRoot);
                using var installed = File.OpenRead(installedUpdater);
                var next = new AgentUpdateLkgPromotion(watch.AttemptId, plan.Version, plan.Sha256, previousHost.UpdaterSha256,
                    Hash(installed), plan.ManifestDigest!, Path.GetFileName(stage));
                store.WritePromotion(next);
                promotion = next;
            }

            var record = prepared
                ? ReadPrepared(preparedPath, promotion, plan, identity)
                : Prepare(stage, preparedPath, promotion, plan, identity);
            log(LkgProbe.PassedLogMarker);

            if (RequireRuntime(watch) != identity) throw InvalidPromotion();
            var current = readJournal();
            if (!LkgWatchHostBinding.BindsWatch(current, watch.AttemptId) || current.Phase != active.Phase ||
                current.LifecycleGeneration != active.LifecycleGeneration || current.WatchRequestedUtc != active.WatchRequestedUtc)
                return Fail(current, changeJournal, promotion, verifiedPlan: null);

            Publish(stage, promotion, record);
            AgentUpdateRollbackFloor.Raise(store.UpdatesRoot, record.Version, "watch_pass", record.ManifestSequence,
                record.ManifestDigest, record.PromotedUtc);
            if (!Close(changeJournal, active, plan, failureCode: null)) return false;
            committed = true;
            Cleanup(promotion);
            return true;
        }
        catch (Exception ex) when (IsPromotionFailure(ex))
        {
            if (committed || (!resume && ex is IOException && promotion is not null))
            {
                // Resume will revalidate intact prepared bytes after an interrupted write.
                LogFailure(log);
                return false;
            }
            return Fail(active, changeJournal, promotion, runtimeVerified ? plan : null);
        }
    }

    internal static void LogFailure(Action<string> log) => log(AgentUpdateWatchJournal.LkgPromotionFailed);

    private static bool IsPromotionFailure(Exception ex) =>
        AgentUpdateRollbackGrant.IsStorageFailure(ex) || ex is CryptographicException or Win32Exception;

    private static bool IsTerminalFailure(AgentUpdateJournal active, string attempt) =>
        active.FailureCode == AgentUpdateWatchJournal.LkgPromotionFailed && active.FailureAttemptId == attempt;

    private AgentUpdateLkgRecord Prepare(string stage, string preparedPath, AgentUpdateLkgPromotion promotion,
        AgentUpdatePlan plan, RuntimeIdentity identity)
    {
        // Before the preparation record exists, no canonical names can have been changed by this attempt.
        DeleteStage(stage);
        Directory.CreateDirectory(stage);
        Validate(stage, allowMissing: false);

        var attempt = AgentUpdateSecurity.ResolveAttemptDirectory(store.UpdatesRoot, promotion.AttemptId);
        var manifest = Path.Combine(attempt, AgentUpdateSecurity.ManifestFileName);
        var msi = Path.Combine(attempt, AgentUpdateSecurity.ArtifactFileName);
        if (plan.ManifestPath is null || !SamePath(plan.ManifestPath, manifest) || !SamePath(plan.ArtifactPath, msi))
            throw InvalidPromotion();

        var stagedManifest = Path.Combine(stage, AgentUpdateSecurity.ManifestFileName);
        Validate(manifest, allowMissing: false);
        using (var source = File.OpenRead(manifest))
        {
            if (source.Length is <= 0 or > AgentUpdateDurableFile.MaxBytes) throw InvalidPromotion();
            Copy(source, stagedManifest);
        }
        var signed = VerifyManifest(stagedManifest, plan);

        var stagedMsi = Path.Combine(stage, AgentUpdateSecurity.ArtifactFileName);
        Validate(msi, allowMissing: false);
        using (var source = File.OpenRead(msi))
        {
            AgentUpdateArtifactTransfer.ValidateFileLength(signed, source.Length);
            Copy(source, stagedMsi);
        }
        using (OpenVerified(stagedMsi, promotion.MsiSha256, signed.ArtifactLength)) { }

        var installedUpdater = Path.Combine(identity.RuntimeRoot, AgentUpdateLkgStore.UpdaterFileName);
        var stagedUpdater = Path.Combine(stage, AgentUpdateLkgStore.UpdaterFileName);
        validateInstalledSource(installedUpdater, identity.RuntimeRoot);
        using (var source = File.OpenRead(installedUpdater)) Copy(source, stagedUpdater);
        using (OpenVerified(stagedUpdater, promotion.NewUpdaterSha256))
            if (!probe(stagedUpdater, plan.Version)) throw InvalidPromotion();

        var record = BuildRecord(promotion, signed, identity, DateTimeOffset.UtcNow);
        AgentUpdateLkgStore.WriteRecord(preparedPath, store.UpdatesRoot, record);
        return record;
    }

    private AgentUpdateLkgRecord ReadPrepared(string path, AgentUpdateLkgPromotion promotion, AgentUpdatePlan plan,
        RuntimeIdentity identity)
    {
        var stage = Path.GetDirectoryName(path)!;
        var signed = VerifyManifest(StagedOrCanonical(stage, store.ManifestPath), plan);
        using (OpenVerified(StagedOrCanonical(stage, store.MsiPath), promotion.MsiSha256, signed.ArtifactLength)) { }
        using (OpenVerified(StagedOrCanonical(stage, store.HostPath), promotion.NewUpdaterSha256)) { }
        var record = JsonSerializer.Deserialize<AgentUpdateLkgRecord>(AgentUpdateLkgStore.ReadSmallFile(path), AgentUpdateLkgStore.RecordJson)
            ?? throw InvalidPromotion();
        if (record.PromotedUtc == default || record.PromotedUtc.Offset != TimeSpan.Zero ||
            record != BuildRecord(promotion, signed, identity, record.PromotedUtc))
            throw InvalidPromotion();
        return record;
    }

    private static AgentUpdateLkgRecord BuildRecord(AgentUpdateLkgPromotion promotion, AgentUpdateManifest signed,
        RuntimeIdentity identity, DateTimeOffset now)
        => new(AgentUpdateLkgStore.Schema, signed.Version, identity.ProductCode, signed.Sha256,
            AgentUpdateArtifactTransfer.ExpectedLength(signed), promotion.ManifestDigest, signed.Sequence,
            signed.EffectiveSignerKeyIdentity!, identity.ServiceExeSha256, promotion.NewUpdaterSha256, promotion.AttemptId, now);

    private AgentUpdateManifest VerifyManifest(string path, AgentUpdatePlan plan)
    {
        Validate(path, allowMissing: false);
        var manifest = AgentUpdateManifestValidator.VerifyStoredSignature(Encoding.UTF8.GetString(AgentUpdateLkgStore.ReadSmallFile(path)),
            _manifestKeys);
        if (manifest.ArtifactKind != "msi" || manifest.Version != plan.Version || manifest.Channel != plan.Channel ||
            manifest.Channel != metadata.ReleaseChannel || manifest.Sequence != plan.Sequence ||
            !SameHash(manifest.Sha256, plan.Sha256) || manifest.ArtifactLength != plan.ArtifactLength ||
            !SameHash(AgentUpdateManifestValidator.Digest(manifest), plan.ManifestDigest) ||
            !string.Equals(manifest.EffectiveSignerKeyIdentity, plan.SignerKeyIdentity, StringComparison.OrdinalIgnoreCase) ||
            !metadata.AllowedSignerKeyIdentity.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Contains(manifest.EffectiveSignerKeyIdentity, StringComparer.OrdinalIgnoreCase))
            throw InvalidPromotion();
        return manifest;
    }

    private RuntimeIdentity RequireRuntime(AgentUpdateWatchRecord watch)
    {
        var identity = readRuntimeIdentity();
        if (identity is null || identity.Version != watch.WatchedVersion || identity.ProductCode != watch.WatchedProductCode ||
            !AgentUpdateManifestValidator.IsSha256(identity.ServiceExeSha256) || !Path.IsPathFullyQualified(identity.RuntimeRoot))
            throw InvalidPromotion();
        var service = Path.Combine(identity.RuntimeRoot, "Cerberus.Agent.Service.exe");
        validateInstalledSource(service, identity.RuntimeRoot);
        using var image = File.OpenRead(service);
        if (!SameHash(Hash(image), identity.ServiceExeSha256)) throw InvalidPromotion();
        return identity;
    }

    private void Publish(string stage, AgentUpdateLkgPromotion promotion, AgentUpdateLkgRecord record)
    {
        Validate(store.RecordPath, allowMissing: true);
        Validate(store.HostPath, allowMissing: true);
        Validate(store.HostRecordPath, allowMissing: true);
        var currentUpdater = File.Exists(store.HostPath) ? HashProtectedFile(store.HostPath) : null;
        if (currentUpdater is not null && !SameHash(currentUpdater, promotion.OldUpdaterSha256) &&
            !SameHash(currentUpdater, promotion.NewUpdaterSha256))
            throw InvalidPromotion();

        PreservePreviousHost(promotion);

        // Retire metadata before replacing either payload so mixed old/new files cannot be used as an LKG.
        if (!HasPublishedRecord(record)) Retire(store.RecordPath, promotion.AttemptId, ".lkg.json");
        Install(stage, store.MsiPath, promotion.AttemptId, ".msi");
        Install(stage, store.ManifestPath, promotion.AttemptId, ".manifest.json");
        if (!SameHash(currentUpdater, promotion.NewUpdaterSha256))
            Install(stage, store.HostPath, promotion.AttemptId, ".exe");

        AgentUpdateLkgStore.WriteRecord(store.RecordPath, store.UpdatesRoot, record);
        AgentUpdateLkgStore.WriteRecord(store.HostRecordPath, store.UpdatesRoot, new AgentUpdateLkgHostRecord(
            AgentUpdateLkgStore.HostSchema, record.Version, record.UpdaterSha256, "promotion", record.PromotedUtc,
            record.WatchedAttemptId, record.Version));
    }

    private bool HasPublishedRecord(AgentUpdateLkgRecord record)
    {
        if (!File.Exists(store.RecordPath)) return false;
        try
        {
            return JsonSerializer.Deserialize<AgentUpdateLkgRecord>(AgentUpdateLkgStore.ReadSmallFile(store.RecordPath),
                AgentUpdateLkgStore.RecordJson) == record;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException) { return false; }
    }

    private bool IsPublished(AgentUpdateLkgPromotion promotion, long sequence)
    {
        Validate(store.RecordPath, allowMissing: false);
        var lkg = JsonSerializer.Deserialize<AgentUpdateLkgRecord>(AgentUpdateLkgStore.ReadSmallFile(store.RecordPath),
            AgentUpdateLkgStore.RecordJson);
        var host = store.ReadHost();
        var floor = AgentUpdateRollbackFloor.Read(store.UpdatesRoot);
        if (!(sequence > 0 && lkg is not null && lkg.Schema == AgentUpdateLkgStore.Schema &&
            lkg.WatchedAttemptId == promotion.AttemptId && lkg.Version == promotion.NewVersion && lkg.ManifestSequence == sequence &&
            SameHash(lkg.ManifestDigest, promotion.ManifestDigest) && SameHash(lkg.MsiSha256, promotion.MsiSha256) &&
            SameHash(lkg.UpdaterSha256, promotion.NewUpdaterSha256) &&
            host is { PlacedBy: "promotion" } && host.AttemptId == promotion.AttemptId && host.LkgVersion == lkg.Version &&
            host.UpdaterVersion == lkg.Version && SameHash(host.UpdaterSha256, lkg.UpdaterSha256) &&
            floor is not null && AgentVersionComparer.CompareReleaseCore(floor.MinVersion, lkg.Version) is >= 0))
            return false;

        Validate(store.ManifestPath, allowMissing: false);
        var manifest = AgentUpdateManifestValidator.VerifyStoredSignature(
            Encoding.UTF8.GetString(AgentUpdateLkgStore.ReadSmallFile(store.ManifestPath)), _manifestKeys);
        Validate(store.MsiPath, allowMissing: false);
        using var msi = File.OpenRead(store.MsiPath);
        AgentUpdateLkgStore.ValidateRelease(lkg!, manifest, promotion.NewVersion, floor, msi.Length, Hash(msi));
        return SameHash(HashProtectedFile(store.HostPath), promotion.NewUpdaterSha256);
    }

    private void Install(string stage, string destination, string attemptId, string suffix)
    {
        var source = Path.Combine(stage, Path.GetFileName(destination));
        if (!File.Exists(source)) return; // ReadPrepared already verified the canonical copy.
        Validate(source, allowMissing: false);
        Retire(destination, attemptId, suffix);
        File.Move(source, destination);
    }

    private void Retire(string path, string attemptId, string suffix)
    {
        Validate(path, allowMissing: true);
        if (!File.Exists(path)) return;
        var retired = RetiredPath(attemptId, suffix);
        Validate(retired, allowMissing: true);
        File.Move(path, retired);
    }

    private void Cleanup(AgentUpdateLkgPromotion promotion)
    {
        DeleteStage(Path.Combine(store.Root, promotion.StageDir));
        foreach (var destination in new[] { store.HostPath, store.HostRecordPath, store.RecordPath, store.MsiPath,
            store.ManifestPath, RetiredPath(promotion.AttemptId, PreviousHostSuffix) })
        {
            var pending = destination + ".restore.tmp";
            Validate(pending, allowMissing: true);
            File.Delete(pending);
        }
        var marker = Path.Combine(store.Root, AgentUpdateLkgStore.PromotionFileName);
        Validate(marker, allowMissing: false);
        if (store.ReadPromotion() != promotion) throw InvalidPromotion();
        File.Delete(marker);
        foreach (var suffix in RetiredSuffixes[..^2])
        {
            var path = RetiredPath(promotion.AttemptId, suffix);
            Validate(path, allowMissing: true);
            File.Delete(path);
        }
    }

    private void DeleteStage(string stage)
    {
        Validate(stage, allowMissing: true);
        if (!Directory.Exists(stage)) return;
        foreach (var file in Directory.EnumerateFiles(stage))
        {
            Validate(file, allowMissing: false);
            File.Delete(file);
        }
        Directory.Delete(stage);
    }

    private FileStream OpenVerified(string path, string expectedHash, long? expectedLength = null)
    {
        Validate(path, allowMissing: false);
        var stream = File.OpenRead(path);
        try
        {
            if (stream.Length <= 0 || (expectedLength is not null && stream.Length != expectedLength) ||
                !SameHash(Hash(stream), expectedHash))
                throw InvalidPromotion();
            verifyArtifact(path, expectedHash);
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static bool Close(Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> changeJournal,
        AgentUpdateJournal active, AgentUpdatePlan? plan, string? failureCode)
        => AgentUpdateJournalPatch.TryApply(changeJournal, active.AttemptId!, active.Phase,
            before => before.LifecycleGeneration != active.LifecycleGeneration || before.WatchRequestedUtc != active.WatchRequestedUtc ||
                (before.Phase == AgentUpdateWatchJournal.CommittedWatch && !LkgWatchHostBinding.BindsWatch(before, active.AttemptId!)) ||
                (failureCode is not null && IsTerminalFailure(before, active.AttemptId!))
                ? null : before with
            {
                Phase = AgentUpdateStates.Installed,
                HealthyInstalledVersion = plan?.Version ?? before.HealthyInstalledVersion,
                HealthyInstalledSequence = plan?.Sequence ?? before.HealthyInstalledSequence,
                FailureCode = failureCode,
                FailureAttemptId = failureCode is null ? null : active.AttemptId,
                FailureInstallerResultId = failureCode is null ? null : before.InstallerResult?.ResultId,
                WatchOutcomeCode = failureCode,
                WatchOutcomeAttemptId = failureCode is null ? null : active.AttemptId,
                AlertCode = failureCode,
                AlertAttemptId = failureCode is null ? null : active.AttemptId,
                InstallerProcessId = null,
                InstallerStartedUtc = null,
            });

    private static void RequirePassedWatch(AgentUpdateWatchRecord watch, AgentUpdatePlan plan)
    {
        watch.Validate();
        if (watch.Outcome != AgentUpdateWatchOutcomes.Passed || plan.SchemaVersion != AgentUpdaterContract.PlanSchema ||
            plan.ArtifactKind != "msi" || plan.AttemptId != watch.AttemptId || plan.Version != watch.WatchedVersion ||
            plan.Sequence != watch.WatchedSequence || plan.ArtifactLength is null or <= 0 ||
            !AgentUpdateManifestValidator.IsSha256(plan.ManifestDigest) || !AgentUpdateManifestValidator.IsSha256(plan.Sha256))
            throw InvalidPromotion();
    }

    private static bool MatchesPlan(AgentUpdateLkgPromotion promotion, AgentUpdatePlan plan)
        => promotion.AttemptId == plan.AttemptId && promotion.NewVersion == plan.Version &&
           SameHash(promotion.MsiSha256, plan.Sha256) && SameHash(promotion.ManifestDigest, plan.ManifestDigest);

    private static string StagedOrCanonical(string stage, string canonical)
    {
        var staged = Path.Combine(stage, Path.GetFileName(canonical));
        return File.Exists(staged) ? staged : canonical;
    }

    private string RetiredPath(string attemptId, string suffix) => Path.Combine(store.Root, RetiredPrefix + attemptId + suffix);
    private void Validate(string path, bool allowMissing) => validateProtectedPath(path, store.UpdatesRoot, allowMissing);

    private string HashProtectedFile(string path)
    {
        Validate(path, allowMissing: false);
        using var file = File.OpenRead(path);
        return Hash(file);
    }

    private static void Copy(FileStream input, string path)
    {
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough);
        input.CopyTo(output);
        output.Flush(flushToDisk: true);
    }

    private static string Hash(Stream stream) => Convert.ToHexStringLower(SHA256.HashData(stream));
    private static bool SameHash(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static bool SamePath(string left, string right) => string.Equals(Path.GetFullPath(left), right, StringComparison.OrdinalIgnoreCase);
    private static InvalidOperationException InvalidPromotion() => new("LKG promotion could not be verified.");
}
