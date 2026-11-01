using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static partial class AgentUpdateLocalService
{
    /// <summary>Called only after the same trusted plan and lifecycle have been reverified.</summary>
    internal static AgentUpdateJournal TransitionVerifiedRequiredPolicy(AgentUpdateJournal current,
        bool required, long? signalGeneration, long lifecycleGeneration, DateTimeOffset verifiedAt)
    {
        if (!required || signalGeneration != lifecycleGeneration || current.LifecycleGeneration != lifecycleGeneration ||
            !IsPreservedPreInstallAttempt(current) ||
            (current.Phase == AgentUpdateStates.Blocked && current.ReconciliationSnapshot is null))
            return current;

        var applyAt = current.ApplyNotBeforeUtc;
        if (current.Phase == AgentUpdateStates.AwaitingConsent && (!current.Required || applyAt is null))
        {
            var rolloutAt = verifiedAt.Add(AgentUpdateJournalStore.Offset(
                current.ScheduleSeed + ":rollout:" + current.AttemptId, TimeSpan.FromHours(24)));
            // A new policy may make an unbound consent actionable, but must not postpone an existing due request.
            if (applyAt is null || applyAt > rolloutAt) applyAt = rolloutAt;
        }
        return current with
        {
            Required = true,
            RequiredPolicyGeneration = RequiredPolicyGenerationFor(current, true, signalGeneration),
            RequiredInstallAttemptId = null,
            ApplyNotBeforeUtc = applyAt,
        };
    }
}
