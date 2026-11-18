using System.IO;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal sealed partial class LkgPromotion
{
    private string MarkerPath => Path.Combine(store.Root, AgentUpdateLkgStore.PromotionFileName);

    private static bool OwnsMarker(AgentUpdateJournal journal, AgentUpdateLkgPromotion marker) =>
        marker.PivotStarted is not null && journal.AttemptId == marker.AttemptId &&
        (journal.Phase == AgentUpdateStates.Installed ||
            journal.Phase == AgentUpdateWatchJournal.CommittedWatch && LkgWatchHostBinding.BindsWatch(journal, marker.AttemptId));

    private bool FinishRetained(AgentUpdateJournal active, Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        AgentUpdateWatchRecord? watch, AgentUpdatePlan? plan, AgentUpdateLkgPromotion marker, out bool handled)
    {
        handled = false;
        try
        {
            if (!HasCrossedPivot(marker))
            {
                if (IsTerminalFailure(active, marker.AttemptId)) Cleanup(marker);
                return false;
            }
            if (ReadConsistentLkg() is { } record &&
                (active.Phase == AgentUpdateStates.Installed || FinishCommittedWatch(record)))
            {
                Cleanup(marker);
                handled = true;
                return true;
            }
            if (marker.RetryCount == AgentUpdateLkgPromotion.MaxRetries)
            {
                Alert(change, active, marker.AttemptId);
                return false;
            }
            return RetainForNextStart();
        }
        catch (Exception ex) when (IsPromotionFailure(ex)) { return RetainForNextStart(); }

        bool RetainForNextStart()
        {
            RetainAndRetry(active, change, marker, integrityFailed: false);
            return false;
        }

        bool FinishCommittedWatch(AgentUpdateLkgRecord record)
        {
            if (plan is null || watch is null || !MatchesPlan(marker, plan) ||
                record.WatchedAttemptId != marker.AttemptId || record.ManifestDigest != marker.ManifestDigest)
                return false;
            RequirePassedWatch(watch, plan);
            var identity = RequireRuntime(watch);
            return record.ProductCode == identity.ProductCode &&
                SameHash(record.ServiceExeSha256, identity.ServiceExeSha256) &&
                Close(change, active, plan, failureCode: null);
        }
    }

    private bool HandleFailure(AgentUpdateJournal active, Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        AgentUpdateLkgPromotion? marker, AgentUpdatePlan? verifiedPlan, Exception error)
    {
        var current = ReadMarkerForRecovery(store, validateProtectedPath).Marker;
        if (marker is not null && current is not null && SamePromotionIdentity(current, marker) && OwnsMarker(active, current))
        {
            marker = current;
        }
        else
        {
            if (current?.AttemptId == active.AttemptId || !HasNoAttemptEvidence(store, active.AttemptId, validateProtectedPath))
                return false;
            marker = null;
        }

        if (marker is not null)
        {
            if (error is HostRestoreFailure) Alert(change, active, marker.AttemptId);
            try
            {
                if (HasCrossedPivot(marker))
                    return RetainAndRetry(active, change, Moved(marker), error is PromotionIntegrityFailure);
            }
            catch (Exception ex) when (IsPromotionFailure(ex))
            {
                // Ambiguous disk state can never authorize deletion of staged recovery bytes.
                return RetainAndRetry(active, change, marker, integrityFailed: false);
            }
        }
        if (!Close(change, active, verifiedPlan, AgentUpdateWatchJournal.LkgPromotionFailed))
            return false;
        LogFailure(log);
        if (marker is not null) Cleanup(marker);
        return true;
    }

    private static bool SamePromotionIdentity(AgentUpdateLkgPromotion left, AgentUpdateLkgPromotion right) =>
        left with { PivotStarted = right.PivotStarted, RetryCount = right.RetryCount } == right;

    private bool RetainAndRetry(AgentUpdateJournal active, Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        AgentUpdateLkgPromotion expected, bool integrityFailed)
    {
        try
        {
            var current = ReadMarkerForRecovery(store, validateProtectedPath).Marker;
            if (current is null || !OwnsMarker(active, current) || current.AttemptId != expected.AttemptId ||
                current.ManifestDigest != expected.ManifestDigest)
                return false;
            if (current.PivotStarted != true) return false;
            var count = integrityFailed ? AgentUpdateLkgPromotion.MaxRetries
                : Math.Min(AgentUpdateLkgPromotion.MaxRetries, current.RetryCount!.Value + 1);
            var next = current with { RetryCount = count };
            if (current != next) store.WritePromotion(next);
            if (count < AgentUpdateLkgPromotion.MaxRetries) return true;
            Alert(change, active, current.AttemptId);
        }
        catch (Exception ex) when (IsPromotionFailure(ex))
        {
            // Fail open for host routing when the marker itself cannot be read or durably updated.
            Alert(change, active, expected.AttemptId);
        }
        return false;
    }

    private bool HasCrossedPivot(AgentUpdateLkgPromotion marker)
    {
        if (marker.PivotStarted == true) return true;
        foreach (var suffix in new[] { ".lkg.json", ".msi", ".manifest.json" })
        {
            var retired = RetiredPath(marker.AttemptId, suffix);
            Validate(retired, allowMissing: true);
            if (Exists(retired)) return true;
        }

        // A bootstrap may have had no old LKG to retire. On the first MSI move the
        // prepared record still exists, the staged MSI is gone, and its canonical name exists.
        var stage = Path.Combine(store.Root, marker.StageDir);
        var prepared = Path.Combine(stage, "lkg.json");
        var stagedMsi = Path.Combine(stage, AgentUpdateSecurity.ArtifactFileName);
        Validate(prepared, allowMissing: true);
        Validate(stagedMsi, allowMissing: true);
        Validate(store.MsiPath, allowMissing: true);
        return Exists(prepared) && !Exists(stagedMsi) && Exists(store.MsiPath);
    }

    internal static bool HasNoAttemptEvidence(AgentUpdateLkgStore store, string? attempt,
        Action<string, string, bool> validate)
    {
        if (!AgentUpdateSecurity.IsSafeAttemptId(attempt)) return false;
        try
        {
            var stage = Path.Combine(store.Root, "stage-" + attempt);
            validate(stage, store.UpdatesRoot, true);
            if (Exists(stage)) return false;
            var retiredPrefix = RetiredPrefix + attempt + ".";
            return !Directory.EnumerateFileSystemEntries(store.Root, "retired-*")
                .Any(path => Path.GetFileName(path).StartsWith(retiredPrefix, StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (IsPromotionFailure(ex)) { return false; }
    }

    private void Alert(Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        AgentUpdateJournal active, string? markerAttempt)
    {
        if (markerAttempt is null || !AgentUpdateSecurity.IsSafeAttemptId(active.AttemptId))
        {
            LogFailure(log);
            return;
        }

        try
        {
            if (AgentUpdateJournalPatch.TryApply(change, active.AttemptId!, active.Phase,
                before => before.Revision == active.Revision &&
                    (before.AlertCode is null || before.AlertCode == AgentUpdateWatchJournal.LkgPromotionFailed &&
                        before.AlertAttemptId != markerAttempt) && !IsTerminalFailure(before, markerAttempt)
                    ? before with { AlertCode = AgentUpdateWatchJournal.LkgPromotionFailed, AlertAttemptId = markerAttempt }
                    : null))
                LogFailure(log);
        }
        catch (Exception ex) when (IsPromotionFailure(ex)) { LogFailure(log); }
    }

    private static bool Exists(string path)
    {
        try { _ = File.GetAttributes(path); return true; }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return false; }
    }
}
