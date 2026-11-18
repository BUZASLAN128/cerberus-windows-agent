using System.IO;
using System.Security.Cryptography;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal static class LkgWatchHostBinding
{
    internal static LkgWatchHostWork Create()
    {
        var metadata = UpdaterLab.WatchMetadata(AgentUpdateBuildMetadata.Read(typeof(LkgWatchHostBinding).Assembly));
        var keys = AgentUpdateTrustBuilder.ResolveUpdateManifestPublicKeys(metadata.ManifestPublicKeysB64,
            null, null, null, null);

        AgentUpdateLkgRecord? ReadLkg(AgentUpdateLkgStore store, string? replaced) => ReadEligibleLkg(store, metadata, keys, replaced);

        return new(keys,
            (path, hash) => LkgPromotion.VerifyAuthenticode(metadata, path, hash,
                (_, digest) => UpdaterLab.IsAdmittedWatchArtifact("updater", AgentProductVersion.Get(typeof(Program).Assembly), digest)),
            context => StartSampling(context, ReadLkg),
            CloseWithoutPromotion,
            (context, watch) =>
            {
                if (MatchesVerifiedPlan(context, watch))
                    LkgPromotion.Run(context.Store, context.JournalStore, watch, context.Plan!, metadata,
                        () => ReadPromotionRuntime(context, watch), AdmitPromotedArtifact, context.Log);
            },
            context => LkgPromotion.Resume(context.Store, context.JournalStore, context.Watch, context.Plan, metadata,
                () => context.Watch is { } watch && MatchesVerifiedPlan(context, watch) ? ReadPromotionRuntime(context, watch) : null,
                AdmitPromotedArtifact, context.Log),
            LkgPromotion.CleanupRetired,
            (context, watch) => LkgRollback.Run(context, watch, ReadLkg));
    }

    private static bool AdmitPromotedArtifact(string path, string version, string sha256) => Path.GetFileName(path) switch
    {
        AgentUpdateLkgStore.UpdaterFileName => UpdaterLab.IsAdmittedWatchArtifact("updater", version, sha256),
        AgentUpdateSecurity.ArtifactFileName => UpdaterLab.IsAdmittedWatchArtifact("msi", version, sha256),
        _ => false,
    };

    private static Func<LkgWatchHostTick>? StartSampling(LkgWatchHostContext context,
        Func<AgentUpdateLkgStore, string?, AgentUpdateLkgRecord?> readLkg)
    {
        var active = context.Journal;
        var attempt = active?.Phase == AgentUpdateWatchJournal.CommittedWatch ? active.AttemptId : context.Watch?.AttemptId;
        if (attempt is null) return null;

        var existing = context.Watch is { Outcome: AgentUpdateWatchOutcomes.Open } watch && watch.AttemptId == attempt
            ? watch : null;
        var plan = context.Plan;
        if (existing is null && (plan is null || plan.AttemptId != attempt || !IsCurrentWatch(context, attempt)))
            return null;

        var replaced = existing is null ? active?.HealthyInstalledVersion : existing.ReplacedVersion;
        var eligible = readLkg(context.Store, replaced);
        var watchMinutes = UpdaterLab.WatchMinutes;
        LkgWatchSampling sampling;
        var persistOpen = existing is null;
        if (existing is not null)
        {
            sampling = LkgWatchSampling.Resume(existing);
        }
        else
        {
            var native = LkgWatchHostWindows.Observe();
            if (plan is null || native.Identity is not { } identity) return null;
            var initial = ToObservation(context, attempt, plan.Version, identity.ProductCode, native, eligible is not null);
            if (initial.JournalStillWatchesAttempt != true) return null;
            sampling = LkgWatchSampling.Open(new(attempt, plan.Version, plan.Sequence, identity.ProductCode, replaced,
                eligible?.Version), initial, () => HashObservedImage(native));
        }

        return () =>
        {
            if (persistOpen)
            {
                persistOpen = false;
                return new(sampling.Record, true, AgentUpdateWatchOutcome.Open);
            }

            var native = LkgWatchHostWindows.Observe();
            var record = sampling.Record;
            var observation = ToObservation(context, record.AttemptId, record.WatchedVersion, record.WatchedProductCode,
                native, eligible is not null);
            var result = sampling.Sample(observation, () => HashObservedImage(native), watchMinutes);
            var decision = result.Decision;
            if (decision is AgentUpdateWatchOutcome.RollbackPending or AgentUpdateWatchOutcome.ForwardOnlyFailed)
            {
                decision = context.InstalledManifestVerified && readLkg(context.Store, replaced) is not null
                    ? AgentUpdateWatchOutcome.RollbackPending : AgentUpdateWatchOutcome.ForwardOnlyFailed;
            }

            if (decision == AgentUpdateWatchOutcome.Passed && !MatchesVerifiedPlan(context, record))
                decision = AgentUpdateWatchOutcome.Inconclusive;

            // A routed rollback handler must bind the typed attempt before publishing rollback_pending.
            var outcome = decision switch
            {
                AgentUpdateWatchOutcome.Passed => AgentUpdateWatchOutcomes.Passed,
                AgentUpdateWatchOutcome.Superseded => AgentUpdateWatchOutcomes.Superseded,
                AgentUpdateWatchOutcome.Inconclusive => AgentUpdateWatchOutcomes.Inconclusive,
                AgentUpdateWatchOutcome.ForwardOnlyFailed => AgentUpdateWatchOutcomes.ForwardOnlyFailed,
                AgentUpdateWatchOutcome.Open or AgentUpdateWatchOutcome.RollbackPending => AgentUpdateWatchOutcomes.Open,
                _ => throw new InvalidOperationException("The watch sampling decision is invalid."),
            };
            return new(result.Record with { Outcome = outcome }, result.ShouldPersist, decision);
        };
    }

    private static bool IsCurrentWatch(LkgWatchHostContext context, string attempt)
    {
        if (context.Journal is not { Phase: AgentUpdateWatchJournal.CommittedWatch } expected || !BindsWatch(expected, attempt))
            return false;
        var current = context.JournalStore.Read();
        return current.Phase == AgentUpdateWatchJournal.CommittedWatch && BindsWatch(current, attempt) &&
            current.LifecycleGeneration == expected.LifecycleGeneration && current.WatchRequestedUtc == expected.WatchRequestedUtc;
    }

    internal static bool BindsWatch(AgentUpdateJournal journal, string attempt) =>
        journal.AttemptId == attempt && journal.WatchAttemptId == attempt && journal.WatchRequestedUtc is not null;

    internal static void CloseWithoutPromotion(LkgWatchHostContext context, AgentUpdateWatchRecord watch, string code)
        => CloseWithoutPromotion(context, watch, code, context.JournalStore.Change);

    internal static void CloseWithoutPromotion(LkgWatchHostContext context, AgentUpdateWatchRecord watch, string code,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change)
    {
        if (context.Journal is not { Phase: AgentUpdateWatchJournal.CommittedWatch } expected || !BindsWatch(expected, watch.AttemptId))
            return;

        var installedIsWatched = MatchesVerifiedPlan(context, watch) && LkgWatchHostWindows.ReadInstalledVersion() == watch.WatchedVersion;
        if (!AgentUpdateJournalPatch.TryApply(change, watch.AttemptId, expected.Phase,
            before => before.LifecycleGeneration == expected.LifecycleGeneration && before.WatchRequestedUtc == expected.WatchRequestedUtc &&
                BindsWatch(before, watch.AttemptId)
                ? WithWatchOutcome(before, code, installedIsWatched ? watch.WatchedVersion : null,
                    installedIsWatched ? watch.WatchedSequence : 0)
                : null))
            return;

        context.Log(code);
        if (watch.Outcome == AgentUpdateWatchOutcomes.ForwardOnlyFailed)
            LkgWatchHostWindows.Restart(false, context.JournalStore.Read);
    }

    private static void CloseWithoutPromotion(LkgWatchHostContext context, AgentUpdateWatchRecord watch)
        => CloseWithoutPromotion(context, watch, watch.Outcome switch
        {
            AgentUpdateWatchOutcomes.ForwardOnlyFailed when watch.Alerts.Contains(AgentUpdateWatchJournal.RollbackFailed, StringComparer.Ordinal)
                => AgentUpdateWatchJournal.RollbackFailed,
            AgentUpdateWatchOutcomes.ForwardOnlyFailed => AgentUpdateWatchJournal.PostCommitUnhealthy,
            _ => AgentUpdateWatchJournal.WatchUnavailable,
        });

    internal static AgentUpdateJournal WithWatchOutcome(AgentUpdateJournal before, string code, string? version, long sequence) => before with
    {
        Phase = AgentUpdateStates.Installed,
        HealthyInstalledVersion = version,
        HealthyInstalledSequence = sequence,
        WatchOutcomeCode = code,
        WatchOutcomeAttemptId = before.AttemptId,
        FailureCode = null,
        FailureAttemptId = null,
        FailureInstallerResultId = null,
        AlertCode = null,
        AlertAttemptId = null,
        InstallerProcessId = null,
        InstallerStartedUtc = null,
    };

    private static LkgWatchObservation ToObservation(LkgWatchHostContext context, string attempt, string version,
        Guid productCode, LkgWatchHostObservation native, bool eligibleLkg)
    {
        var runtimeMatches = native.Identity is { } identity && identity.Version == version && identity.ProductCode == productCode;
        var installed = native.InstalledVersion;
        if (!AgentUpdateManifestValidator.IsReleaseVersion(installed) || installed == version && !runtimeMatches)
            installed = null;
        return new(native.Service, native.TickCount, native.NowUtc, installed, IsCurrentWatch(context, attempt),
            native.Generation is { } generation ? generation == context.Journal?.LifecycleGeneration : null,
            eligibleLkg, runtimeMatches ? native.ServiceImageCanonical : null, runtimeMatches ? native.ProcessImageCanonical : null,
            runtimeMatches ? native.Identity?.ServiceExeSha256 : null, ObservedImage(native));
    }

    private static LkgWatchImageStamp? ObservedImage(LkgWatchHostObservation native) =>
        native.ExeSize is { } size && native.ExeMtime is { } mtime ? new(size, mtime) : null;

    private static string? HashObservedImage(LkgWatchHostObservation native)
    {
        if (native.Identity is not { } identity || ObservedImage(native) is not { } expected) return null;
        try
        {
            var file = new FileInfo(identity.ServicePath);
            bool MatchesStamp() => file.Exists && file.Length == expected.Size && file.LastWriteTimeUtc == expected.LastWriteUtc.UtcDateTime;

            if (!MatchesStamp()) return null;
            var sha256 = LkgWatchHostWindows.HashCanonicalService(identity);
            file.Refresh();
            return MatchesStamp() ? sha256 : null;
        }
        catch (Exception ex) when (LkgWatchHost.IsHostFailure(ex)) { return null; }
    }

    private static AgentUpdateLkgRecord? ReadEligibleLkg(AgentUpdateLkgStore store, AgentUpdateBuildMetadata metadata,
        IReadOnlyList<string> keys, string? replaced)
    {
        if (replaced is null) return null;
        try
        {
            if (!UpdaterLab.IsLabBuild)
                return store.Validate(replaced, keys, metadata.ReleaseChannel, metadata.AllowedSignerKeyIdentity, allowUnsignedDevBuild: false);

            AgentUpdateSecurity.ValidateProtectedPath(store.MsiPath, store.UpdatesRoot, allowMissing: false);
            using var msi = File.OpenRead(store.MsiPath);
            var hash = Convert.ToHexStringLower(SHA256.HashData(msi));
            if (metadata.ReleaseChannel != "dev" || !metadata.AllowUnsignedDevBuild || metadata.AllowedSignerKeyIdentity != "unsigned-dev" ||
                !UpdaterLab.IsAdmittedWatchArtifact("msi", replaced, hash))
                return null;
            // Keep the receipt-bound bytes open through the store's signature, floor, hash and Authenticode checks.
            return store.Validate(replaced, keys, metadata.ReleaseChannel, metadata.AllowedSignerKeyIdentity, allowUnsignedDevBuild: true);
        }
        catch (Exception ex) when (LkgWatchHost.IsHostFailure(ex)) { return null; }
    }

    private static bool MatchesVerifiedPlan(LkgWatchHostContext context, AgentUpdateWatchRecord watch)
        => context.InstalledManifestVerified && context.Plan is { } plan && plan.AttemptId == watch.AttemptId &&
            plan.Version == watch.WatchedVersion && plan.Sequence == watch.WatchedSequence;

    private static LkgPromotion.RuntimeIdentity? ReadPromotionRuntime(LkgWatchHostContext context, AgentUpdateWatchRecord watch)
    {
        var native = LkgWatchHostWindows.Observe();
        if (native.Identity is not { } identity || native.InstalledVersion != watch.WatchedVersion ||
            identity.Version != watch.WatchedVersion || identity.ProductCode != watch.WatchedProductCode ||
            native.Generation is not { } generation || generation != context.Journal?.LifecycleGeneration ||
            native.ServiceImageCanonical != true || native.ProcessImageCanonical != true ||
            native.Service is not { State: AgentUpdateWatchServiceState.Running, ProcessId: > 0, ProcessStartedUtc: not null,
                InstallerMutexHeld: false, CanonicalImagePendingRename: false } || !IsCurrentWatch(context, watch.AttemptId))
            return null;

        return new(identity.Version, identity.ProductCode, identity.ServiceExeSha256, identity.RuntimeRoot);
    }
}
