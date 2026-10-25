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
                // A stopped service never finishes its cleanup; the caller turns this into service_not_ready.
                if (host.GetServiceState() == HeadlessServiceState.Stopped)
                    break;
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

    /// <summary>
    /// Re-reads the service state right before the proof is sent. Returns <c>service_not_ready</c> when the service was
    /// stopped or replaced since <paramref name="initial"/>, or is stopped while its cleanup is still pending; otherwise null.
    /// </summary>
    internal static string? ServiceNotReady(IHeadlessHost host, HeadlessServiceState initial, AgentLifecycleSnapshot state, bool hasCredentials)
    {
        if (initial == HeadlessServiceState.NotInstalled)
            return null;
        var now = host.GetServiceState();
        if (now is HeadlessServiceState.Other or HeadlessServiceState.NotInstalled)
            return "service_not_ready";
        var cleanupPending = HeadlessEnrollmentGate.Refusal(state, hasCredentials) == "cleanup_pending";
        return now == HeadlessServiceState.Stopped && (initial != HeadlessServiceState.Stopped || cleanupPending) ? "service_not_ready" : null;
    }

    /// <summary>
    /// True when the service committed the staged enrollment: the lifecycle generation moved past <paramref name="before"/>,
    /// the state is Active and machine credentials exist. Used after a cancelled adopt round-trip; uses its own short deadline.
    /// </summary>
    internal static async Task<bool> AdoptionCommittedAsync(IHeadlessHost host, AgentLifecycleSnapshot before, IAgentLogger log)
    {
        try
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var now = await host.LoadLifecycleAsync(cleanup.Token).ConfigureAwait(false);
            return now.Generation > before.Generation && now.State == AgentLifecycleState.Active &&
                   now.QuiescenceComplete && host.HasMachineCredentials();
        }
        catch (Exception ex)
        {
            log.Error($"Enrollment state after cancellation could not be read ({ex.GetType().Name}).");
            return false;
        }
    }
}
