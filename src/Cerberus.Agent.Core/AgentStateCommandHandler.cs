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

    /// <param name="currentAgentId">The current credential's agent id, read per call (pass the provider wrapped by <see cref="AgentSignedStateStore.Track"/>).</param>
    /// <param name="lifecycle">Records the revoke. Its quiesce delegate runs on the queue worker, so it must not await
    /// the queue's <c>StopAsync</c> or <c>DisposeAsync</c>.</param>
    /// <param name="cancelExecution">Cancels the execution queue; pass <c>queue.CancelAll</c>, never <c>StopAsync</c>
    /// (the follow-up runs on the queue worker).</param>
    public AgentStateCommandHandler(
        AgentSignedStateStore store,
        Func<CancellationToken, Task<string>> currentAgentId,
        AgentLifecycleController lifecycle,
        Action cancelExecution,
        IAgentLogger? log = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _currentAgentId = currentAgentId ?? throw new ArgumentNullException(nameof(currentAgentId));
        _lifecycle = lifecycle ?? throw new ArgumentNullException(nameof(lifecycle));
        _cancelExecution = cancelExecution ?? throw new ArgumentNullException(nameof(cancelExecution));
        _log = log ?? NullAgentLogger.Instance;
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
            next = next with { PendingRevoke = new AgentPendingRevoke(command.Id, revoke.GetProperty("reason_code").GetString()!) };
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
    /// the signed revoke is applied.
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
            _log.Warn($"agent_state revoke recovery skipped: agent id unavailable ({ex.GetType().Name}).");
            return;
        }

        if (_store.Load(agentId).PendingRevoke is not { } pending)
            return;
        var record = replay.Find(agentId, pending.CommandId);
        var settled = record is { State: EnvelopeRecordStates.Done, ResultSubmitted: true }
                      || (record is null && replay.IsAvailable);
        if (settled)
            await OnResultFinalAsync(agentId, pending.CommandId, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// After the DONE result is final: record the signed revoke, clear it from the store, then cancel the
    /// queue. Ids without a stored pending revoke are ignored. The pending revoke is looked up by
    /// <paramref name="agentId"/>, because the revoke clears the current credential. A revoke applies only to
    /// the registration it was issued for: when the current credential belongs to a different agent id (a
    /// re-enrollment landed first), the pending revoke is cleared without retiring or cancelling anything. If
    /// the current agent id is unavailable (credential already cleared), the revoke is recorded as before.
    /// </summary>
    public async Task OnResultFinalAsync(string agentId, string commandId, CancellationToken ct)
    {
        if (_store.Load(agentId).PendingRevoke is not { } pending
            || !string.Equals(pending.CommandId, commandId, StringComparison.Ordinal))
            return;

        string? currentId = null;
        try
        {
            currentId = await _currentAgentId(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Credential already cleared by an interrupted earlier run: keep the idempotent path.
        }

        if (!string.IsNullOrEmpty(currentId) && !string.Equals(currentId, agentId, StringComparison.Ordinal))
        {
            _log.Warn($"agent_state id={commandId} signed revoke skipped: the registration it was issued for is no longer current.");
            _store.TryClearPendingRevoke(agentId, commandId);
            return;
        }

        var reasonCode = pending.ReasonCode;
        try
        {
            try
            {
                await _lifecycle.RecordTerminalResponseAsync(reasonCode, requestId: null, ct).ConfigureAwait(false);
            }
            catch (AgentRetiredException)
            {
                // Retired is the expected terminal outcome.
            }

            _log.Warn($"agent_state id={commandId} signed revoke recorded reason={reasonCode}.");
            if (!_store.TryClearPendingRevoke(agentId, commandId))
                _log.Warn($"agent_state id={commandId} pending revoke not cleared; it runs again at the next start.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.Error($"agent_state id={commandId} revoke not recorded: {ex.GetType().Name}.");
        }
        finally
        {
            _cancelExecution();
        }
    }

    private sealed record StateResult(
        [property: JsonPropertyName("schema")] string Schema,
        [property: JsonPropertyName("state_seq")] long StateSeq,
        [property: JsonPropertyName("applied")] IReadOnlyList<string> Applied);
}
