using System.Diagnostics;
using System.IO;
using System.Net.Http;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>The installed service owns update decisions. UI/CLI requests contain operations and attempt IDs only.</summary>
internal static partial class AgentUpdateLocalService
{

    /// <summary>
    /// Rewinds only the pre-install state created by the canceled check/stage operation.
    /// Installer evidence and any state that may have crossed the launch fence remain durable.
    /// </summary>
    internal static AgentUpdateJournal TransitionIntentionalCancellation(
        AgentUpdateJournal current,
        AgentUpdateJournal operationStart,
        DateTimeOffset retryAtUtc)
    {
        if (current.Phase == "launch_requested")
            return current with { Phase = AgentUpdateStates.RecoveryRequired };

        if (current.MayHaveStartedInstallation ||
            current.Phase is AgentUpdateStates.Installed or AgentUpdateStates.Blocked or AgentUpdateStates.Quarantined)
            return current;

        var samePriorAttempt = operationStart.AttemptId is not null &&
            string.Equals(current.AttemptId, operationStart.AttemptId, StringComparison.Ordinal);
        if (current.Phase == AgentUpdateStates.Failed && samePriorAttempt)
            return current with { NextCheckUtc = retryAtUtc }; // This is the prior terminal failure, not a synthetic staging failure.

        if (current.Phase == AgentUpdateStates.Current)
            return current with { NextCheckUtc = retryAtUtc };

        if (current.Phase == AgentUpdateStates.Staged)
            return current with
            {
                Phase = AgentUpdateStates.Blocked,
                RequiredPolicyGeneration = RequiredPolicyGenerationFor(current, current.Required, null),
                NextCheckUtc = retryAtUtc,
            };

        if (current.Phase is AgentUpdateStates.AwaitingConsent or AgentUpdateStates.Available)
            return current with
            {
                RequiredPolicyGeneration = RequiredPolicyGenerationFor(current, current.Required, null),
                NextCheckUtc = retryAtUtc,
            };

        if (operationStart.Phase is AgentUpdateStates.Failed or AgentUpdateStates.Installed or
            AgentUpdateStates.Blocked or AgentUpdateStates.Quarantined)
        {
            // The current checking/downloading/failed record belongs to this operation. Keep the
            // earlier terminal evidence, but make the next check immediately eligible.
            return current with
            {
                Phase = operationStart.Phase,
                AttemptId = operationStart.AttemptId,
                Automatic = operationStart.Automatic,
                Required = operationStart.Required,
                LifecycleGeneration = operationStart.LifecycleGeneration,
                RequiredPolicyGeneration = operationStart.RequiredPolicyGeneration,
                RequiredInstallAttemptId = operationStart.RequiredInstallAttemptId,
                InstallRequestAuthorityExpiresUtc = operationStart.InstallRequestAuthorityExpiresUtc,
                InstallerResult = operationStart.InstallerResult,
                FailureCode = operationStart.FailureCode,
                FailureAttemptId = operationStart.FailureAttemptId,
                FailureInstallerResultId = operationStart.FailureInstallerResultId,
                RetryCount = operationStart.RetryCount,
                NextRetryUtc = operationStart.NextRetryUtc,
                BusySinceUtc = operationStart.BusySinceUtc,
                InstallerBusyCount = operationStart.InstallerBusyCount,
                PreInstallFailureCount = operationStart.PreInstallFailureCount,
                PreInstallRetryNotBeforeUtc = operationStart.PreInstallRetryNotBeforeUtc,
                AlertCode = operationStart.AlertCode,
                AlertAttemptId = operationStart.AlertAttemptId,
                ApplyNotBeforeUtc = operationStart.ApplyNotBeforeUtc,
                RunnerProcessId = operationStart.RunnerProcessId,
                RunnerStartedUtc = operationStart.RunnerStartedUtc,
                InstallerProcessId = operationStart.InstallerProcessId,
                InstallerStartedUtc = operationStart.InstallerStartedUtc,
                InstallationBootId = operationStart.InstallationBootId,
                WatchOutcomeCode = operationStart.WatchOutcomeCode,
                WatchOutcomeAttemptId = operationStart.WatchOutcomeAttemptId,
                WatchRequestedUtc = operationStart.WatchRequestedUtc,
                WatchAttemptId = operationStart.WatchAttemptId,
                RollbackAttemptId = operationStart.RollbackAttemptId,
                RollbackStartedUtc = operationStart.RollbackStartedUtc,
                RollbackFirstUtc = operationStart.RollbackFirstUtc,
                RollbackAttemptCount = operationStart.RollbackAttemptCount,
                NextCheckUtc = retryAtUtc,
            };
        }

        return current with
        {
            Phase = AgentUpdateStates.NotChecked,
            AttemptId = null,
            InstallerResult = null,
            RetryCount = 0,
            NextRetryUtc = null,
            BusySinceUtc = null,
            InstallerBusyCount = 0,
            AlertCode = null,
            AlertAttemptId = null,
            ApplyNotBeforeUtc = null,
            RunnerProcessId = null,
            RunnerStartedUtc = null,
            InstallerProcessId = null,
            InstallerStartedUtc = null,
            InstallationBootId = null,
            RequiredPolicyGeneration = null,
            RequiredInstallAttemptId = null,
            InstallRequestAuthorityExpiresUtc = null,
            NextCheckUtc = retryAtUtc,
        };
    }

    internal static bool IsIntentionalCancellation(
        OperationCanceledException error,
        CancellationToken callerToken,
        CancellationToken operationToken,
        bool authorizationChanged)
        => error is IntentionalUpdateCancellationException || authorizationChanged ||
            callerToken.IsCancellationRequested || operationToken.IsCancellationRequested;

    internal static AgentUpdateJournal TransitionBusyRetry(AgentUpdateJournal before, DateTimeOffset now)
    {
        if (IsMsiInstallerBusy(before) && (before.NextRetryUtc is null || InstallerBusyTimeoutDue(before, now)))
            return TransitionInstallerBusy(before, now);
        if (before.Phase != AgentUpdateStates.RetryableBusy || before.NextRetryUtc is not null) return before;
        var next = before with
        {
            RetryCount = Math.Min(3, before.RetryCount + 1),
            NextRetryUtc = now.AddSeconds(Math.Min(30, 4 * Math.Pow(2, before.RetryCount))),
        };
        if (before.RetryCount < 2) return next;
        // An MSI busy/error result remains the cause. Pre-installer retries have no installer result to invent.
        return ProjectedErrorCode(before, AgentUpdateStates.Failed) is null
            ? TransitionFailure(next, AgentUpdateErrorCodes.RetryExhausted)
            : next with { Phase = AgentUpdateStates.Failed };
    }

    internal static AgentUpdateJournal TransitionFailure(AgentUpdateJournal before)
        => before.Phase == "launch_requested" ? before with { Phase = AgentUpdateStates.RecoveryRequired } :
            before.MayHaveStartedInstallation || before.Phase is
            AgentUpdateStates.Installed or AgentUpdateStates.Failed or AgentUpdateStates.Blocked or AgentUpdateStates.Quarantined
            ? before : before with { Phase = AgentUpdateStates.Failed, RequiredPolicyGeneration = null };

    /// <summary>
    /// Records the classified cause only for the failure this call reports: a move into Failed/RecoveryRequired,
    /// or an attempt the stager already failed with no installer result and no cause yet. Never overwrites.
    /// </summary>
    internal static AgentUpdateJournal TransitionFailure(AgentUpdateJournal before, string failureCode)
    {
        var after = TransitionFailure(before);
        var moved = after.Phase != before.Phase && after.Phase is AgentUpdateStates.Failed or AgentUpdateStates.RecoveryRequired;
        var stagerFailed = before.Phase == AgentUpdateStates.Failed && before.InstallerResult is null &&
            (before.FailureCode is null || before.FailureAttemptId != before.AttemptId || before.FailureInstallerResultId is not null);
        return moved || stagerFailed
            ? after with
            {
                FailureCode = failureCode,
                FailureAttemptId = after.AttemptId,
                FailureInstallerResultId = after.InstallerResult?.ResultId,
            }
            : after;
    }

    /// <summary>
    /// Retires a pre-install attempt whose manifest identity no longer matches,
    /// making a fresh trusted stage eligible. Installer/recovery evidence is
    /// never rewound once the launch fence may have been crossed.
    /// </summary>
    internal static AgentUpdateJournal TransitionReconciliationFailure(
        AgentUpdateJournal current,
        DateTimeOffset retryAtUtc,
        bool required = false,
        long? requiredPolicyGeneration = null)
    {
        // A previously retired attempt is already non-applicable. Preserve it
        // exactly, apart from carrying a newly observed required intent.
        if (current.Phase == AgentUpdateStates.Blocked && current.ReconciliationSnapshot is null)
            return required
                ? current with
                {
                    Required = true,
                    RequiredInstallAttemptId = null,
                    InstallRequestAuthorityExpiresUtc = null,
                    RequiredPolicyGeneration = RequiredPolicyGenerationFor(current, true, requiredPolicyGeneration),
                }
                : current with { Required = current.Required && current.RequiredPolicyGeneration is not null,
                    RequiredInstallAttemptId = null, InstallRequestAuthorityExpiresUtc = null };

        if (current.Phase == "launch_requested" ||
            current.MayHaveStartedInstallation ||
            current.Phase is AgentUpdateStates.Installed or AgentUpdateStates.Failed or AgentUpdateStates.Quarantined)
            return current;

        return current with
        {
            Phase = AgentUpdateStates.Blocked,
            Required = required || (current.Required && current.RequiredPolicyGeneration is not null),
            RequiredInstallAttemptId = null,
            InstallRequestAuthorityExpiresUtc = null,
            RequiredPolicyGeneration = RequiredPolicyGenerationFor(
                current,
                required,
                requiredPolicyGeneration),
            NextRetryUtc = null,
            ApplyNotBeforeUtc = null,
            NextCheckUtc = retryAtUtc,
            ReconciliationSnapshot = null,
        };
    }

    /// <summary>
    /// Makes a pre-install attempt non-applicable while retaining the exact
    /// policy, consent, retry and rollout fields needed after the same trusted
    /// manifest identity is verified. A later identity mismatch clears this
    /// snapshot and retires the old release instead.
    /// </summary>
    internal static AgentUpdateJournal TransitionReconciliationDeferred(
        AgentUpdateJournal current,
        DateTimeOffset retryAtUtc,
        bool required = false,
        long? requiredPolicyGeneration = null)
    {
        if (current.Phase == AgentUpdateStates.Blocked && current.ReconciliationSnapshot is null)
            return required
                ? current with
                {
                    Required = true,
                    RequiredPolicyGeneration = RequiredPolicyGenerationFor(current, true, requiredPolicyGeneration),
                }
                : current;

        if (current.Phase == "launch_requested" ||
            current.MayHaveStartedInstallation ||
            current.Phase is AgentUpdateStates.Installed or AgentUpdateStates.Failed or AgentUpdateStates.Quarantined)
            return current;

        var snapshot = current.ReconciliationSnapshot ?? new AgentUpdateReconciliationSnapshot(
            current.Phase,
            current.LifecycleGeneration,
            current.Automatic,
            current.Required,
            current.ApplyNotBeforeUtc,
            current.RetryCount,
            current.NextRetryUtc,
            current.NextCheckUtc);
        return current with
        {
            Phase = AgentUpdateStates.Blocked,
            Required = current.Required || required,
            RequiredPolicyGeneration = RequiredPolicyGenerationFor(
                current,
                required,
                requiredPolicyGeneration),
            NextCheckUtc = retryAtUtc,
            ReconciliationSnapshot = snapshot,
        };
    }

    /// <summary>Restores a deferred attempt only after its identity and lifecycle generation match.</summary>
    internal static AgentUpdateJournal RestoreReconciliationSnapshot(
        AgentUpdateJournal current,
        long lifecycleGeneration,
        DateTimeOffset? retryAtUtc = null,
        bool required = false,
        long? requiredPolicyGeneration = null)
    {
        var snapshot = current.ReconciliationSnapshot;
        if (snapshot is null)
            return current;

        if (snapshot.LifecycleGeneration != lifecycleGeneration)
        {
            // A consent/retry snapshot is scoped to the lifecycle generation
            // that authorized it. Retire the old artifact instead of migrating
            // its policy into a newer enrollment or authorization boundary.
            return TransitionReconciliationFailure(
                current,
                retryAtUtc ?? DateTimeOffset.UtcNow,
                required,
                requiredPolicyGeneration);
        }

        current = ExpireInstallRequestAuthority(current, DateTimeOffset.UtcNow);
        var effectiveRequired = current.Required || required || snapshot.Required &&
            (current.InstallRequestAuthorityExpiresUtc is null || current.InstallRequestAuthorityExpiresUtc > DateTimeOffset.UtcNow);
        var applyNotBeforeUtc = snapshot.ApplyNotBeforeUtc;
        if (applyNotBeforeUtc is null && effectiveRequired && !snapshot.Required &&
            snapshot.Phase == AgentUpdateStates.AwaitingConsent && current.AttemptId is not null)
        {
            // A required signal may arrive while a recommended consent record
            // is deferred. Establish its bounded rollout gate only after the
            // same trusted identity has restored the attempt.
            applyNotBeforeUtc = DateTimeOffset.UtcNow.Add(AgentUpdateJournalStore.Offset(
                current.ScheduleSeed + ":rollout:" + current.AttemptId, TimeSpan.FromHours(24)));
        }

        return current with
        {
            Phase = snapshot.Phase,
            LifecycleGeneration = lifecycleGeneration,
            Automatic = snapshot.Automatic,
            Required = effectiveRequired,
            RequiredPolicyGeneration = RequiredPolicyGenerationFor(
                current,
                effectiveRequired,
                requiredPolicyGeneration),
            RequiredInstallAttemptId = required && requiredPolicyGeneration == lifecycleGeneration
                ? null : current.RequiredInstallAttemptId,
            InstallRequestAuthorityExpiresUtc = required && requiredPolicyGeneration == lifecycleGeneration
                ? null : current.InstallRequestAuthorityExpiresUtc,
            ApplyNotBeforeUtc = applyNotBeforeUtc,
            RetryCount = snapshot.RetryCount,
            NextRetryUtc = snapshot.NextRetryUtc,
            NextCheckUtc = snapshot.NextCheckUtc,
            ReconciliationSnapshot = null,
        };
    }

    /// <summary>
    /// Recovers an interrupted pre-install record that no longer has an attempt
    /// identity. Only current-generation explicit required provenance survives;
    /// an unbound consent or terminal/history record cannot authorize a stage.
    /// </summary>
    internal static AgentUpdateJournal TransitionInterruptedPreInstallWithoutAttempt(
        AgentUpdateJournal current,
        long lifecycleGeneration,
        DateTimeOffset retryAtUtc,
        bool required = false,
        long? requiredPolicyGeneration = null)
    {
        var retainedRequired = current.Required && current.RequiredPolicyGeneration == lifecycleGeneration;
        var effectiveRequired = required || retainedRequired;
        return current with
        {
            Phase = AgentUpdateStates.NotChecked,
            AttemptId = null,
            RequiredInstallAttemptId = null,
            InstallRequestAuthorityExpiresUtc = null,
            LifecycleGeneration = lifecycleGeneration,
            Required = effectiveRequired,
            RequiredPolicyGeneration = effectiveRequired
                ? requiredPolicyGeneration ?? lifecycleGeneration
                : null,
            InstallerResult = null,
            RetryCount = 0,
            NextRetryUtc = null,
            ApplyNotBeforeUtc = null,
            RunnerProcessId = null,
            RunnerStartedUtc = null,
            InstallerProcessId = null,
            InstallerStartedUtc = null,
            InstallationBootId = null,
            ReconciliationSnapshot = null,
            NextCheckUtc = retryAtUtc,
        };
    }

    /// <summary>Starts a check while carrying only current-generation required provenance.</summary>
    internal static AgentUpdateJournal TransitionCheckStart(
        AgentUpdateJournal before,
        bool automatic,
        bool required,
        long lifecycleGeneration,
        DateTimeOffset nextCheckUtc,
        long? requiredPolicyGeneration = null)
        => before with
        {
            AttemptId = null,
            InstallerResult = null,
            FailureCode = null,
            FailureAttemptId = null,
            FailureInstallerResultId = null,
            Phase = AgentUpdateStates.Checking,
            RequiredInstallAttemptId = null,
            InstallRequestAuthorityExpiresUtc = null,
            Automatic = automatic,
            LifecycleGeneration = lifecycleGeneration,
            Required = required,
            RequiredPolicyGeneration = RequiredPolicyGenerationForResult(
                before, required, lifecycleGeneration, requiredPolicyGeneration),
            NextCheckUtc = nextCheckUtc,
        };

    /// <summary>Finishes a check, making a newly available required release immediately schedulable.</summary>
    internal static AgentUpdateJournal TransitionCheckResult(
        AgentUpdateJournal before,
        bool available,
        bool required,
        long lifecycleGeneration,
        long? requiredPolicyGeneration = null,
        DateTimeOffset? now = null)
        => before with
        {
            AttemptId = null,
            InstallerResult = null,
            FailureCode = null,
            FailureAttemptId = null,
            FailureInstallerResultId = null,
            Phase = available ? AgentUpdateStates.Available : AgentUpdateStates.Current,
            RequiredInstallAttemptId = null,
            InstallRequestAuthorityExpiresUtc = null,
            Required = available && required,
            RequiredPolicyGeneration = RequiredPolicyGenerationForResult(
                before, available && required, lifecycleGeneration, requiredPolicyGeneration),
            NextCheckUtc = available && required ? now ?? DateTimeOffset.UtcNow : before.NextCheckUtc,
        };

    /// <summary>Starts staging with a required policy bound to the current lifecycle generation.</summary>
    internal static AgentUpdateJournal TransitionStageStart(
        AgentUpdateJournal before,
        bool automatic,
        bool required,
        long lifecycleGeneration,
        DateTimeOffset nextCheckUtc,
        long? requiredPolicyGeneration = null)
        => before with
        {
            Phase = AgentUpdateStates.Checking,
            AttemptId = null,
            RequiredInstallAttemptId = null,
            InstallRequestAuthorityExpiresUtc = null,
            InstallerResult = null,
            FailureCode = null,
            FailureAttemptId = null,
            FailureInstallerResultId = null,
            Automatic = automatic,
            LifecycleGeneration = lifecycleGeneration,
            Required = required,
            RequiredPolicyGeneration = RequiredPolicyGenerationForResult(
                before, required, lifecycleGeneration, requiredPolicyGeneration),
            RetryCount = 0,
            NextRetryUtc = null,
            BusySinceUtc = null,
            InstallerBusyCount = 0,
            AlertCode = null,
            AlertAttemptId = null,
            ApplyNotBeforeUtc = null,
            RunnerProcessId = null,
            RunnerStartedUtc = null,
            InstallerProcessId = null,
            InstallerStartedUtc = null,
            InstallationBootId = null,
            WatchOutcomeCode = null,
            WatchOutcomeAttemptId = null,
            WatchRequestedUtc = null,
            WatchAttemptId = null,
            RollbackAttemptId = null,
            RollbackStartedUtc = null,
            RollbackFirstUtc = null,
            RollbackAttemptCount = 0,
            NextCheckUtc = nextCheckUtc,
        };

    /// <summary>Commits a staged outcome without dropping its current-generation policy provenance.</summary>
    internal static AgentUpdateJournal TransitionStageResult(
        AgentUpdateJournal before,
        AgentUpdatePlan? plan,
        bool automatic,
        bool required,
        long lifecycleGeneration,
        DateTimeOffset now,
        long? requiredPolicyGeneration = null)
        => before with
        {
            Phase = plan is null ? AgentUpdateStates.Current : AgentUpdateStates.AwaitingConsent,
            RequiredInstallAttemptId = null,
            InstallRequestAuthorityExpiresUtc = null,
            Automatic = automatic,
            LifecycleGeneration = lifecycleGeneration,
            Required = required,
            RequiredPolicyGeneration = RequiredPolicyGenerationForResult(
                before, plan is not null && required, lifecycleGeneration, requiredPolicyGeneration),
            ApplyNotBeforeUtc = plan is null || !required ? null : now.Add(AgentUpdateJournalStore.Offset(
                before.ScheduleSeed + ":rollout:" + plan.Channel + ":" + plan.Sequence, TimeSpan.FromHours(24))),
            NextCheckUtc = now.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
            PreInstallFailureCount = 0,
            PreInstallRetryNotBeforeUtc = null,
        };
}
