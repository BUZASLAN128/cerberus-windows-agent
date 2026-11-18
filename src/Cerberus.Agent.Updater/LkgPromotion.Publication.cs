using System.IO;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal sealed partial class LkgPromotion
{
    private AgentUpdateLkgPromotion Publish(string stage, AgentUpdateLkgPromotion promotion, AgentUpdateLkgRecord record)
    {
        Validate(store.RecordPath, allowMissing: true);
        Validate(store.HostPath, allowMissing: true);
        Validate(store.HostRecordPath, allowMissing: true);
        var updater = Exists(store.HostPath) ? HashProtectedFile(store.HostPath) : null;
        if (updater is not null && !SameHash(updater, promotion.OldUpdaterSha256) && !SameHash(updater, promotion.NewUpdaterSha256))
            throw InvalidPromotion();

        PreservePreviousHost(stage, promotion);
        checkpoint?.Invoke("backup");

        // Remove the old record before changing any payload. Retired names are evidence of a
        // completed rename if the process died before it could checkpoint the pivot.
        if (!HasPublishedRecord(record) && Retire(store.RecordPath, promotion.AttemptId, ".lkg.json"))
            Moved("retire_record");
        Install(store.MsiPath, ".msi", "msi");
        Install(store.ManifestPath, ".manifest.json", "manifest");
        if (!SameHash(updater, promotion.NewUpdaterSha256))
        {
            var preparedHost = Path.Combine(stage, AgentUpdateLkgStore.UpdaterFileName);
            using (OpenVerified(preparedHost, promotion.NewUpdaterSha256, promotion.NewVersion)) { }
            if (Retire(store.HostPath, promotion.AttemptId, ".exe"))
                Moved("retire_host");
            // The verified temp is ready before the canonical image is renamed away.
            File.Move(preparedHost, store.HostPath);
            Moved("move_host");
        }

        AgentUpdateLkgStore.WriteRecord(store.RecordPath, store.UpdatesRoot, record);
        checkpoint?.Invoke("write_record");
        AgentUpdateLkgStore.WriteRecord(store.HostRecordPath, store.UpdatesRoot, new AgentUpdateLkgHostRecord(
            AgentUpdateLkgStore.HostSchema, record.Version, record.UpdaterSha256, "promotion", record.PromotedUtc,
            record.WatchedAttemptId, record.Version));
        checkpoint?.Invoke("write_host");
        return promotion;

        void Install(string destination, string suffix, string name)
        {
            var source = Path.Combine(stage, Path.GetFileName(destination));
            if (!Exists(source)) return; // ReadPrepared verified the canonical copy.
            Validate(source, allowMissing: false);
            if (Retire(destination, promotion.AttemptId, suffix))
                Moved("retire_" + name);
            File.Move(source, destination);
            Moved("move_" + name);
        }

        void Moved(string step)
        {
            checkpoint?.Invoke(step);
            if (promotion.PivotStarted == true) return;
            promotion = promotion with { PivotStarted = true };
            store.WritePromotion(promotion);
        }
    }

    private void PreservePreviousHost(string stage, AgentUpdateLkgPromotion promotion)
    {
        var backup = RetiredPath(promotion.AttemptId, PreviousHostSuffix);
        Validate(backup, allowMissing: true);
        if (Exists(backup) || HasCrossedPivot(promotion)) return;
        var pending = Path.Combine(stage, "previous-host.tmp");
        Validate(pending, allowMissing: true);
        File.Delete(pending);
        using (var input = File.OpenRead(store.HostRecordPath)) Copy(input, pending);
        File.Move(pending, backup);
    }

    private bool HasPublishedRecord(AgentUpdateLkgRecord record)
    {
        if (!Exists(store.RecordPath)) return false;
        try
        {
            return JsonSerializer.Deserialize<AgentUpdateLkgRecord>(AgentUpdateLkgStore.ReadSmallFile(store.RecordPath),
                AgentUpdateLkgStore.RecordJson) == record;
        }
        catch (JsonException) { return false; }
    }

    private AgentUpdateLkgRecord? ReadConsistentLkg()
    {
        Validate(store.RecordPath, allowMissing: false);
        Validate(store.HostRecordPath, allowMissing: false);
        var record = JsonSerializer.Deserialize<AgentUpdateLkgRecord>(AgentUpdateLkgStore.ReadSmallFile(store.RecordPath),
            AgentUpdateLkgStore.RecordJson) ?? throw InvalidPromotion();
        var host = store.ReadHost();
        var floor = AgentUpdateRollbackFloor.Read(store.UpdatesRoot);
        if (host is null || floor is null || !SameHash(HashProtectedFile(store.HostPath), host.UpdaterSha256) ||
            (host.LkgVersion is not null && host.LkgVersion != record.Version) ||
            (host.PlacedBy == "promotion" &&
                (host.AttemptId != record.WatchedAttemptId || !SameHash(host.UpdaterSha256, record.UpdaterSha256))))
            return null;

        Validate(store.ManifestPath, allowMissing: false);
        var manifest = AgentUpdateManifestValidator.VerifyStoredSignature(
            Encoding.UTF8.GetString(AgentUpdateLkgStore.ReadSmallFile(store.ManifestPath)), _manifestKeys);
        if (manifest.ArtifactKind != "msi" || manifest.Channel != metadata.ReleaseChannel) return null;
        using var msi = OpenVerified(store.MsiPath, record.MsiSha256, record.Version, record.MsiLength);
        AgentUpdateLkgStore.ValidateRelease(record, manifest, record.Version, floor, msi.Length, record.MsiSha256);
        return record;
    }

    private bool Retire(string path, string attemptId, string suffix)
    {
        Validate(path, allowMissing: true);
        if (!Exists(path)) return false;
        var retired = RetiredPath(attemptId, suffix);
        Validate(retired, allowMissing: true);
        File.Move(path, retired, overwrite: true);
        return true;
    }

    private void Cleanup(AgentUpdateLkgPromotion promotion)
    {
        Validate(MarkerPath, allowMissing: false);
        if (store.ReadPromotion() != promotion) throw InvalidPromotion();
        DeleteStage(Path.Combine(store.Root, promotion.StageDir));
        File.Delete(MarkerPath);
        foreach (var suffix in RetiredSuffixes[..^2])
        {
            var path = RetiredPath(promotion.AttemptId, suffix);
            Validate(path, allowMissing: true);
            File.Delete(path);
        }
    }
}
