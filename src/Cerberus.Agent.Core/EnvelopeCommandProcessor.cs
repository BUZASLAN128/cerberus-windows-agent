using System.Collections.Concurrent;

namespace Cerberus.Agent.Core;

/// <summary>
/// Inline phase for signed command envelopes (contract v1): checks 1-18, the durable
/// reservation, a 10 s-bounded ack and inline <c>agent_state</c>. No entry starts once
/// <see cref="InlineBudget"/> has passed in a call; entries not reached stay unacked and
/// unreserved. <c>ping</c>, <c>collect_facts</c>, result submission and the outbox run in
/// <see cref="EnvelopeExecutionQueue"/>. Desktop forwards entries without an envelope to the
/// legacy processor unchanged; the server build has no unsigned path.
/// </summary>
public sealed class EnvelopeCommandProcessor : IHeartbeatCommandProcessor
{
    public const int MaxEntriesPerHeartbeat = 8;
    public static readonly TimeSpan InlineBudget = TimeSpan.FromSeconds(20);
    public static readonly TimeSpan AckTimeout = TimeSpan.FromSeconds(10);

    private readonly AgentApiClient _api;
    private readonly EnvelopeExecutionQueue _queue;
    private readonly CommandEnvelopeVerifier _verifier;
    private readonly IAgentLogger _log;
    private readonly ConcurrentDictionary<string, long> _rejections = new(StringComparer.Ordinal);
#if !CERBERUS_SERVER_PROFILE
    private readonly IHeartbeatCommandProcessor? _legacy;
#endif

    /// <param name="anchors">Command trust anchors; the service passes the embedded ones.</param>
    /// <param name="allowedTypes">Types accepted inside an envelope. Default: the server set in the
    /// server build, the queue's handler types on desktop.</param>
    /// <param name="legacy">Desktop only: the processor for entries without an envelope. Ignored by the server build.</param>
    public EnvelopeCommandProcessor(
        AgentApiClient api,
        IReadOnlyList<CommandTrustAnchor> anchors,
        EnvelopeExecutionQueue queue,
        IReadOnlySet<string>? allowedTypes = null,
        IAgentLogger? log = null,
        IHeartbeatCommandProcessor? legacy = null)
    {
        _api = api ?? throw new ArgumentNullException(nameof(api));
        _queue = queue ?? throw new ArgumentNullException(nameof(queue));
        _log = log ?? NullAgentLogger.Instance;
#if CERBERUS_SERVER_PROFILE
        var types = allowedTypes ?? EnvelopeTypes.ServerSet;
#else
        var types = allowedTypes ?? new HashSet<string>(queue.HandlerTypes, StringComparer.Ordinal);
        _legacy = legacy;
#endif
        _verifier = new CommandEnvelopeVerifier(anchors ?? Array.Empty<CommandTrustAnchor>(), types, _log);
    }

    /// <summary>Per-code rejection counters since start.</summary>
    public IReadOnlyDictionary<string, long> RejectionCounts => _rejections;

    public async Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct)
    {
        try
        {
            var envelopes = new List<AgentCommand>();
            var unsigned = new List<AgentCommand>();
            foreach (var command in commands)
                (command is not null && CommandEnvelopeVerifier.HasEnvelope(command) ? envelopes : unsigned).Add(command!);

            if (envelopes.Count > 0)
                await ProcessEnvelopesAsync(envelopes, ct).ConfigureAwait(false);

#if CERBERUS_SERVER_PROFILE
            foreach (var _ in unsigned)
                LogRejection(new EnvelopeCheck(1, EnvelopeCodes.Unsigned, false, null));
#else
            if (unsigned.Count > 0)
            {
                if (_legacy is null)
                    _log.Warn($"Commands without an envelope dropped: no legacy processor (count={unsigned.Count}).");
                else
                    await _legacy.ProcessAsync(unsigned, ct).ConfigureAwait(false);
            }
#endif
        }
        finally
        {
            _queue.SignalHeartbeat();
        }
    }

    public void SignalOutbox() => _queue.SignalHeartbeat();

    private async Task ProcessEnvelopesAsync(List<AgentCommand> envelopes, CancellationToken ct)
    {
        var agentId = await _queue.CurrentAgentIdAsync(ct).ConfigureAwait(false);
        var time = _queue.Time;
        var startedUtc = time.GetUtcNow();
        var startedTimestamp = time.GetTimestamp();
        var ordered = envelopes
            .OrderBy(c => string.Equals(c.Type, EnvelopeTypes.AgentState, StringComparison.Ordinal) ? 0 : 1)
            .Take(MaxEntriesPerHeartbeat);
        foreach (var entry in ordered)
        {
            var elapsed = Max(time.GetUtcNow() - startedUtc, time.GetElapsedTime(startedTimestamp));
            if (elapsed >= InlineBudget)
            {
                _log.Info("Command envelope inline budget spent; remaining entries wait for the next heartbeat.");
                return;
            }

            try
            {
                await ProcessEntryAsync(entry, agentId, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (AgentLifecycleDormantException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _log.Error($"Command envelope entry failed: {ex.GetType().Name}.");
            }
        }
    }

    private async Task ProcessEntryAsync(AgentCommand entry, string agentId, CancellationToken ct)
    {
        var check = _verifier.VerifyEntry(entry, agentId);
        if (!check.Passed)
        {
            await RejectAsync(check, agentId, ct).ConfigureAwait(false);
            return;
        }

        var envelope = check.Envelope!;
        var store = _queue.Store;
        var existing = store.Find(agentId, envelope.Id);
        if (existing is not null)
        {
            if (!string.Equals(existing.EnvelopeSha256, envelope.EnvelopeSha256, StringComparison.Ordinal))
            {
                LogRejection(new EnvelopeCheck(13, EnvelopeCodes.IdConflict, false, envelope));
                return;
            }

            if (_queue.IsInFlight(agentId, envelope.Id))
                return;

            switch (existing.State)
            {
                case EnvelopeRecordStates.RejectedAfterReserve:
                    // The rejected ack may not have arrived; send it again with the stored reason. Nothing runs.
                    if (existing.RejectReason is not null)
                        await TrySendAckAsync(agentId, envelope, accepted: false, existing.RejectReason, ct).ConfigureAwait(false);
                    return;
                case EnvelopeRecordStates.Started:
                    _queue.RecoverOrphan(existing);
                    return;
                case EnvelopeRecordStates.Done:
                    await TrySendAckAsync(agentId, envelope, accepted: true, reason: null, ct).ConfigureAwait(false);
                    return;
            }
        }

        var window = CommandEnvelopeVerifier.CheckReplayWindow(
            envelope,
            _queue.Time.GetUtcNow().ToUnixTimeSeconds(),
            store.ResetAt,
            store.IsNonceUsed(agentId, envelope.Nonce, envelope.Id));
        if (!window.Passed)
        {
            await RejectReservedOrNewAsync(existing, window, agentId, ct).ConfigureAwait(false);
            return;
        }

        if (_queue.IsQuarantined() && envelope.Type is not (EnvelopeTypes.Ping or EnvelopeTypes.AgentState))
        {
            await RejectReservedOrNewAsync(existing, EnvelopeCheck.Fail(17, EnvelopeCodes.Quarantined, ack: true, envelope),
                agentId, ct).ConfigureAwait(false);
            return;
        }

        var queued = envelope.Type != EnvelopeTypes.AgentState;
        if (queued && !_queue.TryAcquireSlot())
        {
            _log.Info($"Command envelope id={envelope.Id} left unacked: execution queue is full.");
            return;
        }

        var record = existing;
        if (record is null)
        {
            record = new CommandReplayRecord(agentId, envelope.Id, envelope.EnvelopeSha256, envelope.Nonce, envelope.Type,
                envelope.IssuedAt, envelope.ExpiresAt, EnvelopeRecordStates.Reserved, null, null, false);
            var outcome = store.TryReserve(record);
            if (outcome != ReplayReserveOutcome.Reserved)
            {
                if (queued)
                    _queue.ReleaseSlot();
                var code = outcome == ReplayReserveOutcome.Full
                    ? EnvelopeCodes.ReplayStoreFull
                    : EnvelopeCodes.ReplayStoreUnavailable;
                await RejectAsync(EnvelopeCheck.Fail(18, code, ack: true, envelope), agentId, ct).ConfigureAwait(false);
                return;
            }
        }

        _queue.MarkInFlight(agentId, envelope.Id);
        if (!await TrySendAckAsync(agentId, envelope, accepted: true, reason: null, ct).ConfigureAwait(false))
        {
            // The record stays reserved and nothing runs; a re-delivery continues at step 14.
            _queue.ClearInFlight(agentId, envelope.Id);
            if (queued)
                _queue.ReleaseSlot();
            return;
        }

        _queue.MarkAccepted(agentId, envelope.Id, envelope.Type);
        _log.Info($"Command accepted id={envelope.Id} type={envelope.Type}");
        if (queued)
            _queue.Enqueue(record, envelope);
        else
            await _queue.ExecuteInlineAsync(record, envelope, ct).ConfigureAwait(false);
    }

    private async Task RejectReservedOrNewAsync(CommandReplayRecord? existing, EnvelopeCheck check, string agentId, CancellationToken ct)
    {
        if (existing is not null
            && _queue.Store.TryUpdate(existing with
            {
                State = EnvelopeRecordStates.RejectedAfterReserve,
                RejectReason = check.AckRejected ? check.Code : null,
            }, EnvelopeRecordStates.Reserved) != ReplayUpdateOutcome.Updated)
            _log.Warn($"Command envelope id={existing.Id} rejection not stored.");
        await RejectAsync(check, agentId, ct).ConfigureAwait(false);
    }

    private async Task RejectAsync(EnvelopeCheck check, string agentId, CancellationToken ct)
    {
        LogRejection(check);
        if (check.AckRejected && check.Envelope is { } envelope)
            await TrySendAckAsync(agentId, envelope, accepted: false, check.Code, ct).ConfigureAwait(false);
    }

    private async Task<bool> TrySendAckAsync(string agentId, SignedEnvelope envelope, bool accepted, string? reason, CancellationToken ct)
    {
        var body = CommandEnvelope.BuildAckBody(envelope.EnvelopeSha256, accepted, reason);
        using var timeout = new CancellationTokenSource(AckTimeout, _queue.Time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        try
        {
            await _api.SubmitEnvelopeAckAsync(agentId, envelope.Id, body, linked.Token)
                .WaitAsync(linked.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (AgentLifecycleDormantException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.Warn($"Command envelope id={envelope.Id} ack not delivered: {ex.GetType().Name}.");
            return false;
        }
    }

    private void LogRejection(EnvelopeCheck check)
    {
        var code = check.Code ?? "unknown";
        var count = _rejections.AddOrUpdate(code, 1, (_, value) => value + 1);
        var id = check.Envelope?.Id ?? "-";
        _log.Warn($"Command envelope rejected code={code} step={check.Step} id={id} count={count}.");
    }

    private static TimeSpan Max(TimeSpan left, TimeSpan right) => left >= right ? left : right;
}
