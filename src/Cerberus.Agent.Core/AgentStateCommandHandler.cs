using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

/// <summary>
/// <c>agent_state</c> (contract v1 (b)). Runs inline in the envelope processor, so quarantine and
/// a revoke gate later entries of the same batch. A <c>state_seq</c> at or below the last applied
/// one fails with <c>stale_state_seq</c> and applies nothing. A revoke is stored with the state
/// (<see cref="AgentPendingRevoke"/>), so it survives a restart, and is recorded through the
/// lifecycle controller only after the DONE result reached a final outcome at the server
/// (<see cref="IEnvelopeResultFollowUp"/>); then the pending revoke is cleared and the execution
/// queue is cancelled.
/// </summary>
public sealed class AgentStateCommandHandler : ICommandHandler, IEnvelopeResultFollowUp
{
    public const string ResultSchema = "agent.state_result.v1";
    public const string StaleStateSeq = "stale_state_seq";

    private readonly AgentSignedStateStore _store;
    private readonly Func<CancellationToken, Task<string>> _currentAgentId;
    private readonly AgentLifecycleController _lifecycle;
    private readonly Action _cancelExecution;
    private readonly IAgentLogger _log;
    private readonly Action _stopAutomaticNetwork;
    private readonly AgentRevokeFinalResults _finalResults;
    private readonly Func<CancellationToken, Task<AgentRevokeRegistration>>? _currentRegistration;
    private int _holdReported;

    /// <param name="currentAgentId">The current credential's agent id, read per call (pass the provider wrapped by <see cref="AgentSignedStateStore.Track"/>).</param>
    /// <param name="lifecycle">Records the revoke. Its quiesce delegate runs on the queue worker, so it must not await
    /// the queue's <c>StopAsync</c> or <c>DisposeAsync</c>.</param>
    /// <param name="cancelExecution">Cancels the execution queue; pass <c>queue.CancelAll</c>, never <c>StopAsync</c>
    /// (the follow-up runs on the queue worker).</param>
    /// <param name="stopAutomaticNetwork">Required. Called when the revoke could not be recorded, so heartbeat and telemetry stop
    /// under the revoked registration; the supervisor restarts the worker, which retries the pending revoke first.</param>
    /// <param name="finalResults">Required. Process-lifetime record shared across worker restarts. A result marked there counts as
    /// final at recovery even when the replay record could not be written or read.</param>
    public AgentStateCommandHandler(
        AgentSignedStateStore store,
        Func<CancellationToken, Task<string>> currentAgentId,
        AgentLifecycleController lifecycle,
        Action cancelExecution,
        IAgentLogger? log,
        Action stopAutomaticNetwork,
        AgentRevokeFinalResults finalResults,
        Func<CancellationToken, Task<AgentRevokeRegistration>>? currentRegistration = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _currentAgentId = currentAgentId ?? throw new ArgumentNullException(nameof(currentAgentId));
        _lifecycle = lifecycle ?? throw new ArgumentNullException(nameof(lifecycle));
        _cancelExecution = cancelExecution ?? throw new ArgumentNullException(nameof(cancelExecution));
        _log = log ?? NullAgentLogger.Instance;
        _stopAutomaticNetwork = stopAutomaticNetwork ?? throw new ArgumentNullException(nameof(stopAutomaticNetwork));
        _finalResults = finalResults ?? throw new ArgumentNullException(nameof(finalResults));
        _currentRegistration = currentRegistration;
    }

    public string Type => EnvelopeTypes.AgentState;

    public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Payload is not JsonElement payload || !CommandEnvelope.IsValidPayload(EnvelopeTypes.AgentState, payload))
            throw new InvalidDataException("agent_state payload is invalid.");

        var agentId = await _currentAgentId(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        var current = _store.Load(agentId);
        var seq = payload.GetProperty("state_seq").GetInt64();
        if (seq <= current.StateSeq)
        {
            _log.Warn($"agent_state id={command.Id} ignored: state_seq {seq} <= {current.StateSeq}.");
            return new CommandResult("FAILED", null, null, StaleStateSeq, null);
        }

        var applied = new List<string>(3);
        var next = current with { StateSeq = seq };
        if (payload.TryGetProperty("registration_state", out var registration))
        {
            next = next with { RegistrationState = registration.GetString() };
            applied.Add("registration_state");
        }

        if (payload.TryGetProperty("quarantine", out var quarantine))
        {
            next = next with { QuarantineActive = quarantine.GetProperty("active").GetBoolean() };
            applied.Add("quarantine");
        }

        if (payload.TryGetProperty("revoke", out var revoke))
        {
            // Stored by the same write as state_seq: the revoke and its quarantine survive a restart.
            var registrationContext = await ReadRegistrationAsync(ct).ConfigureAwait(false);
            if (registrationContext.AgentId != agentId || await _currentAgentId(ct).ConfigureAwait(false) != agentId)
                throw new AgentRegistrationChangedException();
            next = next with { PendingRevoke = new AgentPendingRevoke(command.Id,
                revoke.GetProperty("reason_code").GetString()!, registrationContext) };
            applied.Add("revoke");
        }

        if (!_store.TrySave(next))
            throw new IOException("Signed agent state could not be stored.");

        _log.Info($"agent_state id={command.Id} applied state_seq={seq} quarantine={next.QuarantineActive} revoke={next.PendingRevoke?.ReasonCode ?? "none"}.");
        return new CommandResult("DONE", 0, null, null, new StateResult(ResultSchema, seq, applied));
    }

    /// <summary>
    /// Startup recovery for a crash after the DONE result was delivered and marked submitted, but before the
    /// revoke ran: run the follow-up now. A result still waiting in the outbox is left to the outbox, which
    /// needs the credential. A missing record (retention ended) with a readable store can never be delivered, so
    /// the signed revoke is applied. A result already final in this process (<see cref="AgentRevokeFinalResults"/>)
    /// is applied whatever the replay record says.
    /// </summary>
    public async Task RecoverPendingRevokeAsync(CommandReplayStore replay, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(replay);
        string agentId;
        try
        {
            agentId = await _currentAgentId(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _stopAutomaticNetwork();
            _log.Warn($"agent_state revoke recovery blocked: agent id unavailable ({ex.GetType().Name}); automatic network stays off.");
            return;
        }

        if (_store.Load(agentId).PendingRevoke is not { } pending)
            return;
        var record = replay.Find(agentId, pending.CommandId);
        var settled = _finalResults.Contains(agentId, pending.CommandId)
                      || record is { State: EnvelopeRecordStates.Done, ResultSubmitted: true }
                      || (record is null && replay.IsAvailable);
        if (settled)
            await OnResultFinalAsync(agentId, pending.CommandId, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// After the DONE result is final: record the signed revoke, clear it from the store, then cancel the
    /// queue. Ids without a stored pending revoke are ignored. The pending revoke is looked up by
    /// <paramref name="agentId"/>, because the revoke clears the current credential. A revoke applies only to
    /// the registration it was issued for: when the current credential belongs to a different agent id (a
    /// re-enrollment landed first), tenant, or captured enrollment nonce changed, the pending revoke is
    /// cleared without retiring or cancelling anything. Generation alone is not evidence of another registration. If
    /// current credential metadata is unavailable, the revoke stays pending and the automatic network stops.
    /// Only an already-retired lifecycle permits finishing cleanup without readable credentials.
    /// The result is marked final in the process-lifetime record before the first attempt. If recording fails,
    /// the pending revoke stays stored and the automatic network is stopped.
    /// </summary>
    public async Task OnResultFinalAsync(string agentId, string commandId, CancellationToken ct)
    {
        if (_store.Load(agentId).PendingRevoke is not { } pending
            || !string.Equals(pending.CommandId, commandId, StringComparison.Ordinal))
            return;

        var cancelExecution = true;
        _finalResults.Mark(agentId, commandId);
        try
        {
            // Read before the id: a re-enrollment landing after this read is refused by the generation check below,
            // one landing before it shows as another id.
            var lifecycle = await _lifecycle.LoadAsync(ct).ConfigureAwait(false);
            var generation = lifecycle.Generation;
            string? currentId = null;
            try
            {
                currentId = await _currentAgentId(ct).ConfigureAwait(false);
            }
            catch (AgentRegistrationChangedException)
            {
                if (await DifferentRegistrationAsync(agentId, pending, ct).ConfigureAwait(false) == true)
                {
                    SkipStale(agentId, commandId);
                    cancelExecution = false;
                }
                else
                    HoldRevoke(commandId, "the worker binding changed without proof of a different registration");
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Only an already-retired state proves an interrupted credential cleanup is safe to finish.
                if (lifecycle.State != AgentLifecycleState.Retired)
                {
                    HoldRevoke(commandId, "current credential metadata is unavailable");
                    return;
                }
            }

            if (!string.IsNullOrEmpty(currentId) && !string.Equals(currentId, agentId, StringComparison.Ordinal))
            {
                SkipStale(agentId, commandId);
                cancelExecution = false;
                return;
            }

            var changed = await DifferentRegistrationAsync(agentId, pending, ct).ConfigureAwait(false);
            if (changed == true)
            {
                SkipStale(agentId, commandId);
                cancelExecution = false;
                return;
            }
            if ((changed is null || pending.Registration is null) && lifecycle.State != AgentLifecycleState.Retired)
            {
                HoldRevoke(commandId, pending.Registration is null
                    ? "a legacy revoke has no enrollment context; successful verified re-enrollment is required"
                    : "registration metadata could not be re-read");
                return;
            }

            var reasonCode = pending.ReasonCode;
            var recorded = false;
            try
            {
                var snapshot = await _lifecycle.RecordTerminalResponseAsync(reasonCode, requestId: null, ct, generation).ConfigureAwait(false);
                if (snapshot.State != AgentLifecycleState.Retired && snapshot.Generation != generation)
                {
                    if (await DifferentRegistrationAsync(agentId, pending, ct).ConfigureAwait(false) == true)
                    {
                        SkipStale(agentId, commandId);
                        cancelExecution = false;
                    }
                    else
                        HoldRevoke(commandId, "the lifecycle generation changed without proof of a different registration");
                    return;
                }

                recorded = true;
            }
            catch (AgentRetiredException)
            {
                // Retired is the expected terminal outcome.
                recorded = true;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                // A quiesce or shutdown token can fail the call after the Retired state was saved.
                recorded = await IsRetiredAsync().ConfigureAwait(false);
                if (!recorded)
                {
                    _log.Error($"agent_state id={commandId} revoke not recorded: {ex.GetType().Name}; automatic network stops and the record is retried at the next worker start.");
                    _stopAutomaticNetwork();
                }
            }

            if (recorded)
            {
                _log.Warn($"agent_state id={commandId} signed revoke recorded reason={reasonCode}.");
                if (!_store.TryClearPendingRevoke(agentId, commandId))
                    _log.Warn($"agent_state id={commandId} pending revoke not cleared; it runs again at the next start.");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.Error($"agent_state id={commandId} revoke not recorded: {ex.GetType().Name}; automatic network stops and the record is retried at the next worker start.");
            _stopAutomaticNetwork();
        }
        finally
        {
            if (cancelExecution)
                _cancelExecution();
        }
    }

    private void SkipStale(string agentId, string commandId)
    {
        _log.Warn($"agent_state id={commandId} signed revoke skipped: the registration it was issued for is no longer current.");
        _store.TryClearPendingRevoke(agentId, commandId);
    }

    private async Task<AgentRevokeRegistration> ReadRegistrationAsync(CancellationToken ct)
        => _currentRegistration is not null ? await _currentRegistration(ct).ConfigureAwait(false)
            : new AgentRevokeRegistration(await _currentAgentId(ct).ConfigureAwait(false), null,
                (await _lifecycle.LoadAsync(ct).ConfigureAwait(false)).LastEnrollmentNonce);

    private async Task<bool?> DifferentRegistrationAsync(string agentId, AgentPendingRevoke pending, CancellationToken ct)
    {
        try
        {
            var current = await ReadRegistrationAsync(ct).ConfigureAwait(false);
            // An old file has no context. Only a definitely different agent id can discard it.
            return current.AgentId != agentId || (pending.Registration is { } prior &&
                ((prior.TenantId is not null && current.TenantId is not null && prior.TenantId != current.TenantId)
                 || prior.EnrollmentNonce != current.EnrollmentNonce));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Warn($"Signed revoke registration could not be read ({ex.GetType().Name}).");
            return null;
        }
    }

    private void HoldRevoke(string commandId, string reason)
    {
        if (Interlocked.Exchange(ref _holdReported, 1) == 0)
            _log.Warn($"agent_state id={commandId} pending revoke retained: {reason}; automatic network stays off.");
        _stopAutomaticNetwork();
    }

    private async Task<bool> IsRetiredAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            return (await _lifecycle.LoadAsync(timeout.Token).ConfigureAwait(false)).State == AgentLifecycleState.Retired;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return false;
        }
    }

    private sealed record StateResult(
        [property: JsonPropertyName("schema")] string Schema,
        [property: JsonPropertyName("state_seq")] long StateSeq,
        [property: JsonPropertyName("applied")] IReadOnlyList<string> Applied);
}
