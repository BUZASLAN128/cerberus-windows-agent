using System.IO;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal sealed partial class LkgPromotion
{
    private bool Fail(AgentUpdateJournal active, Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> changeJournal,
        AgentUpdateLkgPromotion? promotion, AgentUpdatePlan? verifiedPlan)
    {
        var attempt = promotion?.AttemptId ?? active.AttemptId!;
        var restored = promotion is null;
        try
        {
            if (promotion is not null) restored = RestorePrevious(promotion);
        }
        catch (Exception ex) when (IsPromotionFailure(ex)) { }

        // The same bound failure is reported once, including legacy markers for which old metadata is unavailable.
        var alreadyFailed = IsTerminalFailure(active, attempt);
        var bound = active.AttemptId == attempt &&
            active.Phase is AgentUpdateWatchJournal.CommittedWatch or AgentUpdateStates.Installed;
        if (bound && !alreadyFailed)
        {
            if (!Close(changeJournal, active, verifiedPlan, AgentUpdateWatchJournal.LkgPromotionFailed))
                return false;
            LogFailure(log);
        }
        if (restored && promotion is not null)
            Cleanup(promotion);
        return false;
    }

    private void PreservePreviousHost(AgentUpdateLkgPromotion promotion)
    {
        var backup = RetiredPath(promotion.AttemptId, PreviousHostSuffix);
        Validate(backup, allowMissing: true);
        if (File.Exists(backup)) return;
        var host = store.ReadHost();
        if (!IsPreviousHost(host, promotion)) return; // A legacy publication may have replaced host.json already.
        ReplaceFrom(store.HostRecordPath, backup);
    }

    private bool RestorePrevious(AgentUpdateLkgPromotion promotion)
    {
        var backup = RetiredPath(promotion.AttemptId, PreviousHostSuffix);
        Validate(backup, allowMissing: true);
        var hasBackup = File.Exists(backup);
        AgentUpdateLkgHostRecord? currentHost = null;
        try { currentHost = store.ReadHost(); }
        catch (Exception ex) when (hasBackup && IsPromotionFailure(ex)) { }
        var oldHost = hasBackup
            ? JsonSerializer.Deserialize<AgentUpdateLkgHostRecord>(AgentUpdateLkgStore.ReadSmallFile(backup), AgentUpdateLkgStore.RecordJson)
            : currentHost;
        if (!IsPreviousHost(oldHost, promotion)) return false;

        var oldExe = PreviousFile(store.HostPath, promotion, ".exe");
        if (!SameHash(HashProtectedFile(oldExe), promotion.OldUpdaterSha256)) return false;

        var oldRecordPath = PreviousFile(store.RecordPath, promotion, ".lkg.json");
        var oldMsi = PreviousFile(store.MsiPath, promotion, ".msi");
        var oldManifest = PreviousFile(store.ManifestPath, promotion, ".manifest.json");
        var changedLkg = oldRecordPath != store.RecordPath || oldMsi != store.MsiPath || oldManifest != store.ManifestPath ||
            hasBackup;
        if (changedLkg)
        {
            var oldRecord = ReadLkgRecord(oldRecordPath);
            if (oldRecord is not null && oldRecord.WatchedAttemptId != promotion.AttemptId)
            {
                ValidateOldLkg(oldRecord, oldMsi, oldManifest);
                // Publish the verified old record last. The monotone floor still decides rollback eligibility.
                ReplaceFrom(oldMsi, store.MsiPath);
                ReplaceFrom(oldManifest, store.ManifestPath);
                ReplaceFrom(oldRecordPath, store.RecordPath);
            }
            else
            {
                // A bootstrap host can have no previous LKG. A legacy or partial marker cannot prove that
                // any remaining canonical payload belongs to the failed publication.
                if (oldHost!.LkgVersion is not null || oldRecordPath != store.RecordPath ||
                    oldMsi != store.MsiPath || oldManifest != store.ManifestPath ||
                    !hasBackup && (File.Exists(oldMsi) || File.Exists(oldManifest)))
                    return false;
                File.Delete(store.RecordPath);
                File.Delete(store.MsiPath);
                File.Delete(store.ManifestPath);
            }
        }
        else if (File.Exists(store.RecordPath) && ReadLkgRecord(store.RecordPath)?.WatchedAttemptId == promotion.AttemptId)
        {
            return false;
        }

        if (oldExe != store.HostPath && (!File.Exists(store.HostPath) ||
            !SameHash(HashProtectedFile(store.HostPath), promotion.OldUpdaterSha256)))
        {
            // The current image may be executing. Preserve it under an attempt-bound retired name.
            Retire(store.HostPath, promotion.AttemptId, FailedHostSuffix);
            ReplaceFrom(oldExe, store.HostPath);
        }
        if (!IsPreviousHost(currentHost, promotion))
            ReplaceFrom(backup, store.HostRecordPath);
        return SameHash(HashProtectedFile(store.HostPath), promotion.OldUpdaterSha256) && IsPreviousHost(store.ReadHost(), promotion);
    }

    private static bool IsPreviousHost(AgentUpdateLkgHostRecord? host, AgentUpdateLkgPromotion promotion) =>
        host is not null && host.Schema == AgentUpdateLkgStore.HostSchema &&
        SameHash(host.UpdaterSha256, promotion.OldUpdaterSha256) &&
        (host.PlacedBy != "promotion" || host.AttemptId != promotion.AttemptId);

    private string PreviousFile(string canonical, AgentUpdateLkgPromotion promotion, string suffix)
    {
        var retired = RetiredPath(promotion.AttemptId, suffix);
        Validate(retired, allowMissing: true);
        Validate(canonical, allowMissing: true);
        return File.Exists(retired) ? retired : canonical;
    }

    private static AgentUpdateLkgRecord? ReadLkgRecord(string path) => File.Exists(path)
        ? JsonSerializer.Deserialize<AgentUpdateLkgRecord>(AgentUpdateLkgStore.ReadSmallFile(path), AgentUpdateLkgStore.RecordJson)
            ?? throw InvalidPromotion()
        : null;

    private void ValidateOldLkg(AgentUpdateLkgRecord record, string msiPath, string manifestPath)
    {
        Validate(manifestPath, allowMissing: false);
        var signed = AgentUpdateManifestValidator.VerifyStoredSignature(
            Encoding.UTF8.GetString(AgentUpdateLkgStore.ReadSmallFile(manifestPath)), _manifestKeys);
        Validate(msiPath, allowMissing: false);
        using var msi = File.OpenRead(msiPath);
        if (record.Schema != AgentUpdateLkgStore.Schema || record.Version != signed.Version ||
            record.ManifestSequence != signed.Sequence || record.MsiLength != signed.ArtifactLength ||
            record.MsiLength != msi.Length || !SameHash(record.ManifestDigest, AgentUpdateManifestValidator.Digest(signed)) ||
            !SameHash(record.MsiSha256, signed.Sha256) || !SameHash(Hash(msi), signed.Sha256))
            throw InvalidPromotion();
    }

    private void ReplaceFrom(string source, string destination)
    {
        if (SamePath(source, destination)) return;
        Validate(source, allowMissing: false);
        Validate(destination, allowMissing: true);
        var pending = destination + ".restore.tmp";
        Validate(pending, allowMissing: true);
        File.Delete(pending);
        using (var input = File.OpenRead(source)) Copy(input, pending);
        File.Move(pending, destination, overwrite: true);
    }
}
