using System.IO;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal static class LkgWatchHostBinding
{
    internal static LkgWatchHostWork CreateSigned(Action<LkgWatchHostContext, AgentUpdateWatchRecord> closeWithoutPromotion)
    {
        ArgumentNullException.ThrowIfNull(closeWithoutPromotion);
        if (UpdaterLab.IsLabBuild)
            throw new InvalidOperationException("Lab watch hosting requires campaign artifact admission.");

        var metadata = AgentUpdateBuildMetadata.Read(typeof(LkgWatchHostBinding).Assembly);
        var keys = AgentUpdateTrustBuilder.ResolveUpdateManifestPublicKeys(metadata.ManifestPublicKeysB64,
            null, null, null, null);

        // Lab admission needs the running host version for self-check, the plan version for promotion,
        // and the replaced version for LKG validation. Bind each kind/version/hash to its campaign receipt.
        static bool DenyUnsigned(string path, string sha256) => false;

        return new(keys, DenyUnsigned,
            context => StartSampling(context, metadata, keys),
            closeWithoutPromotion, // Late writer binds WatchOutcomeCode and WatchOutcomeAttemptId in one CAS.
            (context, watch) =>
            {
                if (MatchesVerifiedPlan(context, watch))
                    LkgPromotion.Run(context.Store, context.JournalStore, watch, context.Plan!,
                        () => ReadPromotionRuntime(context, watch), DenyUnsigned, context.Log);
            },
            context => LkgPromotion.Resume(context.Store, context.JournalStore, context.Watch, context.Plan,
                () => context.Watch is { } watch && MatchesVerifiedPlan(context, watch) ? ReadPromotionRuntime(context, watch) : null,
                DenyUnsigned, context.Log),
            LkgPromotion.CleanupRetired);
    }

    private static Func<LkgWatchHostTick>? StartSampling(LkgWatchHostContext context,
        AgentUpdateBuildMetadata metadata, IReadOnlyList<string> keys)
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
        var eligible = ReadEligibleLkg(context.Store, metadata, keys, replaced);
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
            // The lab duration is carried separately by the compiled policy when its binding lands.
            var result = sampling.Sample(observation, () => HashObservedImage(native),
                (int)AgentUpdateWatchPolicy.RequiredObservation.TotalMinutes);
            var decision = result.Decision;
            if (decision is AgentUpdateWatchOutcome.RollbackPending or AgentUpdateWatchOutcome.ForwardOnlyFailed)
            {
                decision = ReadEligibleLkg(context.Store, metadata, keys, replaced) is not null
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
        if (context.Journal is not { Phase: AgentUpdateWatchJournal.CommittedWatch } expected || expected.AttemptId != attempt)
            return false;
        // The late typed WatchAttemptId joins this check once the committed-watch writer lands.
        var current = context.JournalStore.Read();
        return current.Phase == AgentUpdateWatchJournal.CommittedWatch && current.AttemptId == attempt &&
            current.LifecycleGeneration == expected.LifecycleGeneration;
    }

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
        try { return store.Validate(replaced, keys, metadata.ReleaseChannel, metadata.AllowedSignerKeyIdentity, allowUnsignedDevBuild: false); }
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
