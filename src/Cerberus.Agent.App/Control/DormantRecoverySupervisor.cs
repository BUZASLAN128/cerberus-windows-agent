using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Control;

/// <summary>
/// Server-profile step of the service loop: backend address migration, then the dormant-state
/// probe. Each runs at most once per <see cref="AttemptInterval"/> in this process, counted from
/// before the attempt, so a durable write that keeps failing cannot turn the 2 s loop into a
/// probe or credential-read loop. The interval is below the policy's shortest jittered delay
/// (15 min x 0.75), so the durable schedule stays the binding limit while writes succeed. Both
/// limits reset when the lifecycle generation changes.
/// </summary>
internal sealed class DormantRecoverySupervisor
{
    internal static readonly TimeSpan AttemptInterval = TimeSpan.FromMinutes(10);

    private readonly IAgentLifecycleStateStore _lifecycle;
    private readonly AgentLifecycleController _controller;
    private readonly ISecretStore _secrets;
    private readonly SemaphoreSlim _manualGate;
    private readonly IAgentLogger _log;
    private readonly AgentDormantRecoveryPolicy _policy;
    private readonly Func<IAgentLifecycleStateStore, CancellationToken, Task<bool>> _probe;
    private readonly Func<DateTimeOffset> _clock;
    private long? _generation;
    private (long Generation, AgentLifecycleState State, string? Reason)? _episode;
    private bool _scheduleWritten;
    private DateTimeOffset _nextProbeUtc = DateTimeOffset.MinValue;
    private DateTimeOffset _nextMigrateUtc = DateTimeOffset.MinValue;

    internal DormantRecoverySupervisor(
        IAgentLifecycleStateStore lifecycle,
        AgentLifecycleController controller,
        ISecretStore secrets,
        SemaphoreSlim manualGate,
        IAgentLogger log,
        AgentDormantRecoveryPolicy? policy = null,
        Func<IAgentLifecycleStateStore, CancellationToken, Task<bool>>? probe = null,
        Func<DateTimeOffset>? clock = null)
    {
        _lifecycle = lifecycle;
        _controller = controller;
        _secrets = secrets;
        _manualGate = manualGate;
        _log = log;
        _policy = policy ?? new AgentDormantRecoveryPolicy();
        _probe = probe ?? DormantStateRecovery.HeartbeatProbeAsync;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Runs the due attempts and returns the resulting snapshot. Shutdown cancellation propagates;
    /// any other failure, including a request timeout, is logged once for the attempt.
    /// </summary>
    internal async Task<AgentLifecycleSnapshot> TickAsync(AgentLifecycleSnapshot snapshot, bool awaitingAdoption, CancellationToken ct)
    {
        if (_generation != snapshot.Generation)
        {
            _generation = snapshot.Generation;
            _nextProbeUtc = DateTimeOffset.MinValue;
            _nextMigrateUtc = DateTimeOffset.MinValue;
        }
        snapshot = WithOwnSchedule(snapshot);
        var now = _clock();
#if CERBERUS_SERVER_PROFILE
        await LogReenrollmentRequiredAsync(snapshot, awaitingAdoption, now, ct).ConfigureAwait(false);
#endif
        var migrate = now >= _nextMigrateUtc && DormantStateRecovery.CanMigrate(snapshot, awaitingAdoption);
        if (!migrate && !(now >= _nextProbeUtc && ProbeOrScheduleDue(snapshot, awaitingAdoption)))
            return snapshot;

        // Retry, enrollment-adopt and unregister hold the same gate; when one is running, wait
        // for the next tick without using up the attempt window.
        if (!await _manualGate.WaitAsync(0, ct).ConfigureAwait(false))
            return snapshot;
        try
        {
            if (migrate)
            {
                _nextMigrateUtc = now + AttemptInterval;
                snapshot = await DormantStateRecovery.TryMigrateBackendAsync(_lifecycle, _secrets, snapshot,
                    awaitingAdoption, _log, ct).ConfigureAwait(false);
            }
            if (now >= _nextProbeUtc && ProbeOrScheduleDue(snapshot, awaitingAdoption))
            {
                _nextProbeUtc = now + AttemptInterval;
                var before = snapshot;
                snapshot = await DormantStateRecovery.RunAsync(_lifecycle, _controller, _policy, _probe,
                    snapshot, awaitingAdoption, _log, ct).ConfigureAwait(false);
                // A new revision means the durable store now holds the recovery schedule (or a decision).
                if (snapshot.Revision != before.Revision)
                    _scheduleWritten = true;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.Warn($"Lifecycle recovery attempt could not complete ({ex.GetType().Name}).");
        }
        finally
        {
            _manualGate.Release();
        }
        return snapshot;
    }

#if CERBERUS_SERVER_PROFILE
    private DateTimeOffset _nextReenrollLogUtc = DateTimeOffset.MinValue;

    // NeedsReenrollment is never probed; tell the operator once per interval which key a new proof replaces.
    private async Task LogReenrollmentRequiredAsync(AgentLifecycleSnapshot snapshot, bool awaitingAdoption, DateTimeOffset now, CancellationToken ct)
    {
        if (snapshot.State != AgentLifecycleState.NeedsReenrollment || awaitingAdoption || now < _nextReenrollLogUtc)
            return;
        _nextReenrollLogUtc = now + AttemptInterval;
        string? fingerprint = null;
        try
        {
            var (_, _, privateKeyPem, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
            fingerprint = AgentKeyFingerprint.TryFromPrivateKeyPem(privateKeyPem);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // No readable credentials: nothing to name.
        }
        _log.Warn($"reenrollment_proof_required fingerprint={fingerprint ?? "none"}");
    }
#endif

    // A dormant state can carry the transient-retry backoff (NextAttemptUtc, TransientFailureCount)
    // from before it went dormant. Until this process has started the recovery schedule for the
    // current dormant episode, those values are treated as unset, so the first probe is a full
    // initial delay away and is not shortened or pushed out by the carried values.
    private AgentLifecycleSnapshot WithOwnSchedule(AgentLifecycleSnapshot snapshot)
    {
        if (!AgentDormantRecoveryPolicy.IsRecoverable(snapshot))
            return snapshot;
        var episode = (snapshot.Generation, snapshot.State, snapshot.ReasonCode);
        if (_episode != episode)
        {
            _episode = episode;
            _scheduleWritten = false;
        }
        return _scheduleWritten || snapshot.NextAttemptUtc is null
            ? snapshot
            : snapshot with { NextAttemptUtc = null, TransientFailureCount = 0 };
    }

    private bool ProbeOrScheduleDue(AgentLifecycleSnapshot snapshot, bool awaitingAdoption)
        => !awaitingAdoption && AgentDormantRecoveryPolicy.IsRecoverable(snapshot) &&
            (AgentDormantRecoveryPolicy.NeedsSchedule(snapshot) || _policy.IsDue(snapshot));
}
