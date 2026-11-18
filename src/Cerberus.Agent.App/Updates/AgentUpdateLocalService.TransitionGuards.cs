using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static partial class AgentUpdateLocalService
{
    /// <summary>
    /// Carries an explicit required signal, or durable required-policy
    /// provenance through the pre-stage check states of the same lifecycle
    /// generation. Terminal/history records never become a new policy source.
    /// </summary>
    internal static bool CarryRequiredBlockedIntent(
        AgentUpdateJournal current,
        bool required,
        long lifecycleGeneration)
        => required || (current.Required &&
            (current.Phase is AgentUpdateStates.NotChecked or AgentUpdateStates.Blocked or AgentUpdateStates.Checking or AgentUpdateStates.Available) &&
            ((current.RequiredPolicyGeneration == lifecycleGeneration &&
                (current.Phase is AgentUpdateStates.NotChecked or AgentUpdateStates.Checking or AgentUpdateStates.Available ||
                    current.AttemptId is not null)) ||
             (current.RequiredPolicyGeneration is null && current.RequiredInstallAttemptId is null &&
                current.ReconciliationSnapshot is not null && current.Phase == AgentUpdateStates.Blocked &&
                current.AttemptId is not null && current.LifecycleGeneration == lifecycleGeneration)));

    internal static bool IsRequiredSignalCurrent(
        bool required,
        long capturedGeneration,
        long lifecycleGeneration)
        => required && capturedGeneration == lifecycleGeneration;

    /// <summary>
    /// Retains an existing explicit provenance marker across retries. A newly
    /// received generation may add/advance that marker, while a false-required
    /// retry never manufactures one from the old attempt generation.
    /// </summary>
    private static long? RequiredPolicyGenerationFor(
        AgentUpdateJournal current,
        bool required,
        long? incomingGeneration)
    {
        if (!required)
            return current.RequiredPolicyGeneration;

        if (current.RequiredPolicyGeneration is long existing)
        {
            if (incomingGeneration is long incoming && incoming >= 0)
                return Math.Max(existing, incoming);
            return existing;
        }

        return incomingGeneration is long generation && generation >= 0
            ? generation
            : null;
    }

    private static long? RequiredPolicyGenerationForResult(
        AgentUpdateJournal before,
        bool required,
        long lifecycleGeneration,
        long? incomingGeneration)
        => required
            ? RequiredPolicyGenerationFor(before, true, incomingGeneration) ?? (!before.Required ? lifecycleGeneration : null)
             : null;

}
