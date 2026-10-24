using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Control;

/// <summary>
/// Unattended-profile recovery from AuthSuspect, BlockedConfig and NeedsReenrollment.
/// One heartbeat per due attempt, sent against a throwaway lifecycle store so a failed
/// probe cannot change machine state. Success returns the machine state to Active.
/// Local identity, key and token material are never cleared here.
/// </summary>
internal static class DormantStateRecovery
{
    internal static async Task<AgentLifecycleSnapshot> RunAsync(
        IAgentLifecycleStateStore lifecycle,
        AgentLifecycleController controller,
        AgentDormantRecoveryPolicy policy,
        Func<IAgentLifecycleStateStore, CancellationToken, Task<bool>> probe,
        AgentLifecycleSnapshot snapshot,
        bool awaitingAdoption,
        IAgentLogger log,
        CancellationToken ct)
    {
        if (!AgentDormantRecoveryPolicy.IsRecoverable(snapshot) || awaitingAdoption)
            return snapshot;

        if (AgentDormantRecoveryPolicy.NeedsSchedule(snapshot))
            return await SaveScheduleAsync(lifecycle, policy, snapshot, 0, ct).ConfigureAwait(false);
        if (!policy.IsDue(snapshot))
            return snapshot;

        var probeState = new InMemoryAgentLifecycleStateStore();
        bool recovered;
        try
        {
            recovered = await probe(probeState, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            recovered = false;
            log.Warn($"Lifecycle recovery probe failed ({ex.GetType().Name}); state={snapshot.State}.");
        }

        if (recovered)
        {
            var next = await controller.CompleteScheduledRecoveryAsync(snapshot.Generation, ct).ConfigureAwait(false);
            if (AgentLifecycleStates.AllowsAutomaticNetwork(next.State))
                log.Info("Lifecycle recovery probe succeeded; automatic network resumed.");
            return next;
        }

        return await SaveScheduleAsync(lifecycle, policy, snapshot, snapshot.TransientFailureCount + 1, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// A persisted backend_environment_mismatch block ends when the compiled address now passes
    /// the migration rules: the registered address is replaced, credentials are kept and the
    /// lifecycle returns to Active. Anything else leaves the state unchanged.
    /// </summary>
    internal static async Task<AgentLifecycleSnapshot> TryMigrateBackendAsync(
        AgentLifecycleController controller,
        ISecretStore secrets,
        AgentLifecycleSnapshot snapshot,
        bool awaitingAdoption,
        IAgentLogger log,
        CancellationToken ct,
        string? compiledBackendUrl = null)
    {
        compiledBackendUrl ??= AgentBuildConfig.BackendUrl;
        if (awaitingAdoption || snapshot.State != AgentLifecycleState.BlockedConfig ||
            snapshot.ReasonCode != "backend_environment_mismatch" || !AgentDormantRecoveryPolicy.IsRecoverable(snapshot))
            return snapshot;

        try
        {
            var current = await secrets.LoadAsync(ct).ConfigureAwait(false);
            if (!ServerBackendMigration.ShouldMigrate(current.BackendUrl, compiledBackendUrl,
                    Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL")))
                return snapshot;
            var migrated = await ServerBackendMigration.MigrateAsync(secrets, current, compiledBackendUrl, ct).ConfigureAwait(false);
            log.Info($"Registered backend address updated from {ServerBackendMigration.HostPort(current.BackendUrl)} to {ServerBackendMigration.HostPort(migrated)}.");
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException or InvalidOperationException
            or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException)
        {
            log.Warn($"Registered backend address could not be updated ({ex.GetType().Name}).");
            return snapshot;
        }

        return await controller.CompleteScheduledRecoveryAsync(snapshot.Generation, ct).ConfigureAwait(false);
    }

    /// <summary>Production probe: one heartbeat with the stored machine credentials.</summary>
    internal static async Task<bool> HeartbeatProbeAsync(IAgentLifecycleStateStore probeState, CancellationToken ct)
    {
        var response = await AgentLocalControlService.ProbeAsync(
            new DpapiSecretStore(SecretStoreScope.Machine), probeState, quiesce: null, ct).ConfigureAwait(false);
        return AgentLocalControlService.Claimed(response) &&
            !AgentLifecycleStates.IsDormant((await probeState.LoadAsync(ct).ConfigureAwait(false)).State);
    }

    private static async Task<AgentLifecycleSnapshot> SaveScheduleAsync(
        IAgentLifecycleStateStore lifecycle,
        AgentDormantRecoveryPolicy policy,
        AgentLifecycleSnapshot snapshot,
        int failedAttempts,
        CancellationToken ct)
    {
        var scheduled = policy.Schedule(snapshot, failedAttempts);
        return await lifecycle.TrySaveAsync(scheduled, snapshot.Revision, ct).ConfigureAwait(false)
            ?? await lifecycle.LoadAsync(ct).ConfigureAwait(false);
    }
}
