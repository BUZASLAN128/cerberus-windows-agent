using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Control;

/// <summary>
/// Unattended-profile recovery from AuthSuspect, BlockedConfig and NeedsReenrollment.
/// One heartbeat per due attempt. Probe state stays in a scratch store; credential writes run
/// under the durable lifecycle-generation fence. A terminal, re-enrollment or credential answer
/// is recorded durably for the observed generation, which ends probing. Success returns the
/// machine state to Active. Nothing here clears local identity, key or token material.
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

        var probeState = new FencedProbeLifecycleStore(lifecycle, snapshot.Generation);
        bool recovered;
        try
        {
            recovered = await probe(probeState, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            // A request timeout surfaces as a cancellation while ct is still live: a failed probe.
            recovered = false;
            log.Warn($"Lifecycle recovery probe failed ({ex.GetType().Name}); state={snapshot.State}.");
        }

        var outcome = await probeState.LoadAsync(ct).ConfigureAwait(false);
        if (StopOutcome(outcome) is { } stop)
            return await RecordStopAsync(lifecycle, snapshot, stop.State, stop.Reason, outcome.LastRequestId, log, ct).ConfigureAwait(false);

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
    /// True for dormant, settled states without a terminal, re-enrollment or credential reason:
    /// the states in which the registered address may move to the compiled one.
    /// </summary>
    internal static bool CanMigrate(AgentLifecycleSnapshot snapshot, bool awaitingAdoption)
        => !awaitingAdoption && snapshot.QuiescenceComplete &&
            AgentLifecycleStates.IsDormant(snapshot.State) && snapshot.State != AgentLifecycleState.Retired &&
            !AgentLifecycleStatePolicy.IsTerminalCode(snapshot.ReasonCode) &&
            snapshot.ReasonCode != AgentLifecycleStatePolicy.AgentReenrollRequiredCode &&
            snapshot.ReasonCode?.StartsWith("credentials_", StringComparison.Ordinal) != true;

    /// <summary>
    /// Moves the registered address to the compiled one when the migration rules allow it, under
    /// the durable generation fence. The lifecycle state is kept, except that a BlockedConfig state
    /// caused by backend_url_invalid or backend_environment_mismatch returns to Active when the
    /// local configuration check no longer finds a cause (no network call). Anything else leaves
    /// the state unchanged.
    /// </summary>
    internal static async Task<AgentLifecycleSnapshot> TryMigrateBackendAsync(
        IAgentLifecycleStateStore lifecycle,
        ISecretStore secrets,
        AgentLifecycleSnapshot snapshot,
        bool awaitingAdoption,
        IAgentLogger log,
        CancellationToken ct,
        string? compiledBackendUrl = null)
    {
        if (!CanMigrate(snapshot, awaitingAdoption))
            return snapshot;
        compiledBackendUrl ??= AgentBuildConfig.BackendUrl;
        var environmentBackendUrl = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL");

        try
        {
            await ServerBackendMigration.MigrateIfCurrentAsync(lifecycle, snapshot.Generation, secrets,
                compiledBackendUrl, environmentBackendUrl, log, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ServerBackendMigration.IsStoreFailure(ex))
        {
            log.Warn($"Registered backend address could not be updated ({ex.GetType().Name}).");
            return snapshot;
        }

        if (!AgentBuildProfile.IsServer || !IsLocalConfigBlock(snapshot))
            return snapshot;
        string? storedBackendUrl = null;
        try
        {
            if (!await lifecycle.ExecuteIfCurrentAsync(snapshot.Generation, async cancel =>
                    storedBackendUrl = (await secrets.LoadAsync(cancel).ConfigureAwait(false)).BackendUrl, ct).ConfigureAwait(false))
                return await lifecycle.LoadAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ServerBackendMigration.IsStoreFailure(ex))
        {
            log.Warn($"Registered backend address could not be read ({ex.GetType().Name}).");
            return snapshot;
        }
        if (storedBackendUrl is null || BackendConfigCheck.BlockReason(environmentBackendUrl, storedBackendUrl, compiledBackendUrl) is not null)
            return snapshot;

        var current = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
        if (current.Generation != snapshot.Generation || !IsLocalConfigBlock(current) || !current.QuiescenceComplete)
            return current;
        var clearedReason = current.ReasonCode;
        var resumed = await lifecycle.TrySaveAsync(current with
        {
            State = AgentLifecycleState.Active,
            ReasonCode = null,
            NextAttemptUtc = null,
            GenericAuthFailureCount = 0,
            TransientFailureCount = 0,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        }, current.Revision, ct).ConfigureAwait(false);
        if (resumed is null)
            return await lifecycle.LoadAsync(ct).ConfigureAwait(false);
        log.Info($"Backend configuration block '{clearedReason}' cleared; resuming.");
        return resumed;
    }

    /// <summary>Production probe: one heartbeat with the stored machine credentials.</summary>
    internal static async Task<bool> HeartbeatProbeAsync(IAgentLifecycleStateStore probeState, CancellationToken ct)
    {
        if (probeState is not FencedProbeLifecycleStore fenced)
            throw new InvalidOperationException("Recovery probe requires the fenced lifecycle store.");
        var secrets = new RecoveryProbeSecretStore(new DpapiSecretStore(SecretStoreScope.Machine), fenced);
        if (await CredentialProblemAsync(secrets, ct).ConfigureAwait(false) is { } reason)
        {
            await probeState.TransitionAsync(AgentLifecycleState.NeedsReenrollment, reason, requestId: null,
                nextAttemptUtc: null, genericAuthFailureCount: null, ct).ConfigureAwait(false);
            return false;
        }
        var response = await AgentLocalControlService.ProbeAsync(secrets, probeState, quiesce: null, ct).ConfigureAwait(false);
        return AgentLocalControlService.Claimed(response) &&
            !AgentLifecycleStates.IsDormant((await probeState.LoadAsync(ct).ConfigureAwait(false)).State);
    }

    // Same reason codes as the worker start. InvalidOperationException is left out: it also
    // signals an unresolved credential publication, which is not a credential defect.
    private static async Task<string?> CredentialProblemAsync(ISecretStore secrets, CancellationToken ct)
    {
        try
        {
            var (identity, refreshToken, privateKeyPem, backendUrl, _, _) = await secrets.LoadAsync(ct).ConfigureAwait(false);
            return string.IsNullOrWhiteSpace(identity.AgentId) || string.IsNullOrWhiteSpace(identity.TenantId) ||
                string.IsNullOrWhiteSpace(refreshToken) || string.IsNullOrWhiteSpace(privateKeyPem) ||
                string.IsNullOrWhiteSpace(backendUrl) ? "credentials_invalid" : null;
        }
        catch (Exception ex) when (ex is System.IO.FileNotFoundException or System.IO.DirectoryNotFoundException)
        {
            return "credentials_missing";
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return "credentials_unavailable";
        }
        catch (System.Text.Json.JsonException)
        {
            return "credentials_invalid";
        }
    }

    private static (AgentLifecycleState State, string Reason)? StopOutcome(AgentLifecycleSnapshot outcome)
        => outcome.ReasonCode switch
        {
            { } code when outcome.State == AgentLifecycleState.Retired && AgentLifecycleStatePolicy.IsTerminalCode(code)
                => (AgentLifecycleState.Retired, code),
            { } code when outcome.State == AgentLifecycleState.NeedsReenrollment &&
                (code == AgentLifecycleStatePolicy.AgentReenrollRequiredCode || code.StartsWith("credentials_", StringComparison.Ordinal))
                => (AgentLifecycleState.NeedsReenrollment, code),
            _ => null,
        };

    // Generation-checked compare-and-swap on the durable store. A changed generation means an
    // adopt, unregister or retire already decided the state, so the probe answer is dropped.
    private static async Task<AgentLifecycleSnapshot> RecordStopAsync(IAgentLifecycleStateStore lifecycle,
        AgentLifecycleSnapshot observed, AgentLifecycleState state, string reason, string? requestId, IAgentLogger log, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var saved = await lifecycle.TransitionAsync(state, reason, requestId, nextAttemptUtc: null,
                genericAuthFailureCount: null, ct, expectedGeneration: observed.Generation).ConfigureAwait(false);
            if (saved.State == state && saved.ReasonCode == reason)
            {
                log.Warn($"Lifecycle recovery probe ended recovery; state={saved.State} reason={reason}.");
                return saved;
            }
            if (saved.Generation != observed.Generation || saved.State == AgentLifecycleState.Retired)
                return saved;
        }
        return await lifecycle.LoadAsync(ct).ConfigureAwait(false);
    }

    private static bool IsLocalConfigBlock(AgentLifecycleSnapshot snapshot)
        => snapshot.State == AgentLifecycleState.BlockedConfig &&
            snapshot.ReasonCode is BackendConfigCheck.UrlInvalid or BackendConfigCheck.EnvironmentMismatch;

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
