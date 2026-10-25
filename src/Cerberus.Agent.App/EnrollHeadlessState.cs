using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App;

/// <summary>Reads the local lifecycle state for <see cref="EnrollHeadlessMode"/>, waiting out a service that is still finishing quiescence.</summary>
internal static class EnrollHeadlessState
{
    internal const int MaxQuiescenceWaitSeconds = 60;

    /// <summary>Null when the state cannot be read. Cancellation propagates.</summary>
    internal static async Task<(AgentLifecycleSnapshot State, bool HasCredentials)?> LoadAsync(
        IHeadlessHost host, bool serviceInstalled, IAgentLogger log, CancellationToken ct)
    {
        try
        {
            var state = await host.LoadLifecycleAsync(ct).ConfigureAwait(false);
            var hasCredentials = host.HasMachineCredentials();
            if (!serviceInstalled || HeadlessEnrollmentGate.Refusal(state, hasCredentials) != "cleanup_pending")
                return (state, hasCredentials);

            // A freshly started service moves its lifecycle through quiescence for a moment; no proof has been sent yet.
            log.Info("Waiting for the service to finish its startup cleanup before enrolling.");
            for (var i = 0; i < MaxQuiescenceWaitSeconds; i++)
            {
                await host.DelayAsync(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
                state = await host.LoadLifecycleAsync(ct).ConfigureAwait(false);
                hasCredentials = host.HasMachineCredentials();
                if (HeadlessEnrollmentGate.Refusal(state, hasCredentials) != "cleanup_pending")
                    break;
            }
            return (state, hasCredentials);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Error($"Local enrollment state could not be read ({ex.GetType().Name}).");
            return null;
        }
    }
}
