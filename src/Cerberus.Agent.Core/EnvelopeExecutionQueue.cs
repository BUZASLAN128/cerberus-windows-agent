using System.Collections.Concurrent;
using System.Net;

namespace Cerberus.Agent.Core;

/// <summary>
/// Implemented by an envelope handler that must act only after its result reached a final
/// outcome at the server (2xx, or a 4xx other than 408/429). <c>agent_state</c> revoke uses
/// it so the DONE result is submitted before credentials are cleared.
/// </summary>
public interface IEnvelopeResultFollowUp
{
    Task OnResultFinalAsync(string agentId, string commandId, CancellationToken ct);
}

/// <summary>
/// Serial background executor for envelope commands. At most <see cref="MaxQueued"/> accepted
/// entries wait or run at once. It also stores and submits every envelope result and drains
/// the result outbox after each heartbeat, so none of this runs in the heartbeat loop.
/// </summary>
public sealed class EnvelopeExecutionQueue : IAsyncDisposable
{
    public const int MaxQueued = 8;
    public const int OutboxPerCycle = 16;
    public const int MaxResultBodyBytes = 262144;
    public const string OutcomeUnknown = "OUTCOME_UNKNOWN";

    private readonly AgentApiClient _api;
    private readonly IReadOnlyDictionary<string, ICommandHandler> _handlers;
    private readonly Func<CancellationToken, Task<string>> _currentAgentId;
    private readonly IAgentLogger _log;
    private readonly ConcurrentQueue<QueuedEnvelope> _queue = new();
    private readonly ConcurrentDictionary<(string AgentId, string Id), byte> _inFlight = new();
    private readonly ConcurrentDictionary<(string AgentId, string Id), (string Type, long Started)> _accepted = new();
    private readonly SemaphoreSlim _signal = new(0);
    private readonly SemaphoreSlim _drainGate = new(1, 1);
    private readonly object _lifecycleGate = new();
    private CancellationTokenSource _stop = new();
    private CancellationTokenSource _cancelAll = new();
    private Task? _worker;
    private int _slots;
    private int _outboxRequested;

    public EnvelopeExecutionQueue(
        AgentApiClient api,
        CommandReplayStore store,
        IEnumerable<ICommandHandler> handlers,
        Func<CancellationToken, Task<string>> currentAgentId,
        Func<bool> isQuarantined,
        TimeProvider? time = null,
        IAgentLogger? log = null)
    {
        _api = api ?? throw new ArgumentNullException(nameof(api));
        Store = store ?? throw new ArgumentNullException(nameof(store));
        _handlers = (handlers ?? throw new ArgumentNullException(nameof(handlers)))
            .ToDictionary(h => h.Type, StringComparer.Ordinal);
        _currentAgentId = currentAgentId ?? throw new ArgumentNullException(nameof(currentAgentId));
        IsQuarantined = isQuarantined ?? throw new ArgumentNullException(nameof(isQuarantined));
        Time = time ?? TimeProvider.System;
        _log = log ?? NullAgentLogger.Instance;
    }

    public CommandReplayStore Store { get; }

    public TimeProvider Time { get; }

    /// <summary>Signed quarantine, read at every check (step 17 and before start).</summary>
    public Func<bool> IsQuarantined { get; }

    public IReadOnlyCollection<string> HandlerTypes => _handlers.Keys.ToArray();

    /// <summary>The current credential's agent id, read on every call so a rebind needs no restart.</summary>
    public Task<string> CurrentAgentIdAsync(CancellationToken ct) => _currentAgentId(ct);

    public void Start()
    {
        lock (_lifecycleGate)
            _worker ??= Task.Run(() => RunAsync(_stop.Token));
    }

    public async Task StopAsync()
    {
        Task? worker;
        lock (_lifecycleGate)
        {
            worker = _worker;
            _worker = null;
            _stop.Cancel();
        }

        CancelAll();
        if (worker is not null)
            await worker.ConfigureAwait(false);
        lock (_lifecycleGate)
        {
            _stop.Dispose();
            _stop = new CancellationTokenSource();
        }
    }

    public ValueTask DisposeAsync() => new(StopAsync());

    /// <summary>Cancels the running entry and drops every queued one (stop or revoke).</summary>
    public void CancelAll()
    {
        CancellationTokenSource previous;
        lock (_lifecycleGate)
        {
            previous = _cancelAll;
            _cancelAll = new CancellationTokenSource();
        }

        previous.Cancel();
        previous.Dispose();
        while (_queue.TryDequeue(out var dropped))
        {
            Forget(dropped.Record);
            Finish(dropped.Record);
        }
    }

    /// <summary>Runs one outbox pass (recover orphans, submit stored results) and returns when it ends; runs no command.</summary>
    public Task DrainOutboxOnceAsync(CancellationToken ct) => DrainOutboxAsync(ct);

    /// <summary>Requests one outbox pass; called after every heartbeat.</summary>
    public void SignalHeartbeat()
    {
        Interlocked.Exchange(ref _outboxRequested, 1);
        _signal.Release();
    }

    public int QueuedCount => Volatile.Read(ref _slots);

    internal bool IsInFlight(string agentId, string id) => _inFlight.ContainsKey((agentId, id));

    internal void MarkInFlight(string agentId, string id) => _inFlight[(agentId, id)] = 0;

    internal void ClearInFlight(string agentId, string id) => _inFlight.TryRemove((agentId, id), out _);

    /// <summary>Remembers when an acked entry was accepted, for the duration in the finished log line.</summary>
    internal void MarkAccepted(string agentId, string id, string type)
        => _accepted[(agentId, id)] = (type, Time.GetTimestamp());

    /// <summary>An entry that never ran will not log "Command finished"; drop its accepted marker.</summary>
    private void Forget(CommandReplayRecord record) => _accepted.TryRemove((record.AgentId, record.Id), out _);

    internal bool TryAcquireSlot()
    {
        while (true)
        {
            var current = Volatile.Read(ref _slots);
            if (current >= MaxQueued)
                return false;
            if (Interlocked.CompareExchange(ref _slots, current + 1, current) == current)
                return true;
        }
    }

    internal void ReleaseSlot() => Interlocked.Decrement(ref _slots);

    /// <summary>Queues an acked entry; the caller holds a slot and marked it in flight.</summary>
    internal void Enqueue(CommandReplayRecord record, SignedEnvelope envelope)
    {
        _queue.Enqueue(new QueuedEnvelope(record, envelope));
        _signal.Release();
    }

    /// <summary>Runs an acked <c>agent_state</c> inline; its result is submitted by the background outbox.</summary>
    internal async Task ExecuteInlineAsync(CommandReplayRecord record, SignedEnvelope envelope, CancellationToken ct)
    {
        var keepInFlight = false;
        try
        {
            var started = record with { State = EnvelopeRecordStates.Started };
            if (Store.TryUpdate(started, record.State) != ReplayUpdateOutcome.Updated)
            {
                _log.Error($"Command envelope id={record.Id} not started: replay store write failed.");
                Forget(record);
                return;
            }

            var body = await ExecuteAsync(envelope, ct).ConfigureAwait(false);
            var (done, durable) = StoreResult(started, body);
            // The outbox cannot see a result that is not stored: deliver it from memory, and while the record
            // still reads started keep it in flight so no OUTCOME_UNKNOWN follows a delivered result.
            if (!durable && await SubmitAsync(done, ct, started.State).ConfigureAwait(false))
                keepInFlight = true;
        }
        finally
        {
            if (!keepInFlight)
                ClearInFlight(record.AgentId, record.Id);
        }
    }

    /// <summary>A <c>started</c> record from an earlier process: report OUTCOME_UNKNOWN once, never run again.</summary>
    internal CommandReplayRecord RecoverOrphan(CommandReplayRecord record)
    {
        var body = CommandEnvelope.BuildResultBody(OutcomeUnknown, null, null, null, record.EnvelopeSha256);
        _log.Warn($"Command envelope id={record.Id} was interrupted; reporting {OutcomeUnknown}.");
        return StoreResult(record, body).Record;
    }

    internal static TimeSpan TimeoutFor(string type) => type switch
    {
        EnvelopeTypes.Ping => TimeSpan.FromSeconds(10),
        EnvelopeTypes.AgentState => TimeSpan.FromSeconds(10),
        _ => TimeSpan.FromSeconds(120),
    };

    private async Task RunAsync(CancellationToken stop)
    {
        while (!stop.IsCancellationRequested)
        {
            try
            {
                await _signal.WaitAsync(stop).ConfigureAwait(false);
                while (!stop.IsCancellationRequested && _queue.TryDequeue(out var item))
                    await RunItemAsync(item, stop).ConfigureAwait(false);
                if (Interlocked.Exchange(ref _outboxRequested, 0) == 1)
                    await DrainOutboxAsync(stop).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _log.Error($"Command envelope queue pass failed: {ex.GetType().Name}.");
            }
        }
    }

    private async Task RunItemAsync(QueuedEnvelope item, CancellationToken stop)
    {
        var (record, envelope) = item;
        CancellationTokenSource linked;
        lock (_lifecycleGate)
            linked = CancellationTokenSource.CreateLinkedTokenSource(stop, _cancelAll.Token);
        using var _ = linked;
        var keepInFlight = false;
        try
        {
            var current = await _currentAgentId(linked.Token).ConfigureAwait(false);
            var stored = Store.Find(record.AgentId, record.Id);
            if (!string.Equals(current, record.AgentId, StringComparison.Ordinal)
                || stored?.State != EnvelopeRecordStates.Reserved)
            {
                _log.Warn($"Command envelope id={record.Id} dropped before start: agent id or record changed.");
                Forget(record);
                return;
            }

            var now = Time.GetUtcNow().ToUnixTimeSeconds();
            byte[] body;
            if (now > envelope.ExpiresAt + CommandEnvelopeVerifier.SkewSeconds)
            {
                body = Failed("expired_before_start", record.EnvelopeSha256);
            }
            else if (IsQuarantined() && envelope.Type is not (EnvelopeTypes.Ping or EnvelopeTypes.AgentState))
            {
                body = Failed(EnvelopeCodes.Quarantined, record.EnvelopeSha256);
            }
            else
            {
                var reserved = stored;
                stored = stored with { State = EnvelopeRecordStates.Started };
                if (Store.TryUpdate(stored, reserved.State) != ReplayUpdateOutcome.Updated)
                {
                    _log.Error($"Command envelope id={record.Id} not started: replay store write failed.");
                    Forget(record);
                    return;
                }

                body = await ExecuteAsync(envelope, linked.Token).ConfigureAwait(false);
            }

            var (done, durable) = StoreResult(stored, body);
            var delivered = await SubmitAsync(done, linked.Token, durable ? EnvelopeRecordStates.Done : stored.State)
                .ConfigureAwait(false);
            keepInFlight = delivered && !durable;
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            // Stop or revoke: a started record is reported OUTCOME_UNKNOWN by a later pass.
        }
        catch (Exception ex)
        {
            _log.Error($"Command envelope id={record.Id} failed in the queue: {ex.GetType().Name}.");
        }
        finally
        {
            Finish(record, keepInFlight);
        }
    }

    /// <summary>One pass; stops posting once <see cref="CancelAll"/> fires (a POST already in flight may complete).</summary>
    private async Task DrainOutboxAsync(CancellationToken stop)
    {
        CancellationToken cancelAll;
        lock (_lifecycleGate)
            cancelAll = _cancelAll.Token;
        await _drainGate.WaitAsync(stop).ConfigureAwait(false);
        try
        {
            var agentId = await _currentAgentId(stop).ConfigureAwait(false);
            foreach (var orphan in Store.Records(agentId)
                         .Where(r => r.State == EnvelopeRecordStates.Started && !IsInFlight(r.AgentId, r.Id)))
            {
                if (cancelAll.IsCancellationRequested)
                    return;
                RecoverOrphan(orphan);
            }

            var pending = Store.Records(agentId)
                .Where(r => r.State == EnvelopeRecordStates.Done && !r.ResultSubmitted && r.ResultB64 is not null
                            && !IsInFlight(r.AgentId, r.Id))
                .Take(OutboxPerCycle)
                .ToList();
            foreach (var record in pending)
            {
                stop.ThrowIfCancellationRequested();
                if (cancelAll.IsCancellationRequested)
                    return;
                await SubmitAsync(record, stop).ConfigureAwait(false);
            }
        }
        finally
        {
            _drainGate.Release();
        }
    }

    /// <summary>
    /// POSTs the stored result bytes. Retries stop on 2xx or a 4xx other than 408/429. Returns true once the result
    /// reached a final outcome (delivered or refused); <paramref name="storedState"/> is the state the record must
    /// still hold to be marked submitted.
    /// </summary>
    private async Task<bool> SubmitAsync(CommandReplayRecord record, CancellationToken ct, string storedState = EnvelopeRecordStates.Done)
    {
        if (record.ResultB64 is null || record.ResultSubmitted)
            return false;

        var refused = false;
        var httpStatus = 0;
        try
        {
            await _api.SubmitEnvelopeResultAsync(record.AgentId, record.Id, Convert.FromBase64String(record.ResultB64), ct)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException ex) when (ex.StatusCode is { } status && IsFinalRefusal(status))
        {
            _log.Warn($"Command envelope id={record.Id} result refused with HTTP {(int)status}; not retried.");
            refused = true;
            httpStatus = (int)status;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.Warn($"Command envelope id={record.Id} result not delivered: {ex.GetType().Name}; kept in the outbox.");
            return false;
        }

        if (_accepted.TryRemove((record.AgentId, record.Id), out var accepted))
        {
            var ms = (long)Math.Round(Time.GetElapsedTime(accepted.Started).TotalMilliseconds);
            if (refused)
                _log.Warn($"Command result refused id={record.Id} type={accepted.Type} status={ResultStatus(record)} http={httpStatus} duration_ms={ms}");
            else
                _log.Info($"Command finished id={record.Id} type={accepted.Type} status={ResultStatus(record)} duration_ms={ms}");
        }

        if (Store.TryUpdate(record with { ResultSubmitted = true }, storedState) != ReplayUpdateOutcome.Updated)
            _log.Warn($"Command envelope id={record.Id} result delivered; replay store not updated.");
        if (_handlers.TryGetValue(record.Type, out var handler) && handler is IEnvelopeResultFollowUp followUp)
            await followUp.OnResultFinalAsync(record.AgentId, record.Id, ct).ConfigureAwait(false);
        return true;
    }

    private static string ResultStatus(CommandReplayRecord record)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(Convert.FromBase64String(record.ResultB64!));
            return doc.RootElement.GetProperty("status").GetString() ?? "UNKNOWN";
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return "UNKNOWN";
        }
    }

    private async Task<byte[]> ExecuteAsync(SignedEnvelope envelope, CancellationToken ct)
    {
        if (!_handlers.TryGetValue(envelope.Type, out var handler))
            return Failed("handler_exception", envelope.EnvelopeSha256);

        var command = new AgentCommand(envelope.Id, envelope.Type, envelope.Id, envelope.Payload);
        using var timeout = new CancellationTokenSource(TimeoutFor(envelope.Type), Time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        CommandResult result;
        try
        {
            result = await InvokeAsync(handler, command, linked.Token).WaitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return Failed("command_timeout", envelope.EnvelopeSha256);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.Warn($"Command envelope id={envelope.Id} handler failed: {ex.GetType().Name}.");
            return Failed("handler_exception", envelope.EnvelopeSha256);
        }

        if (result is null || result.Status is not ("DONE" or "FAILED"))
            return Failed("handler_exception", envelope.EnvelopeSha256);

        var body = CommandEnvelope.BuildResultBody(result.Status, result.ExitCode, result.Stderr, result.PostVerify,
            envelope.EnvelopeSha256);
        return body.Length <= MaxResultBodyBytes ? body : Failed("result_too_large", envelope.EnvelopeSha256);
    }

    /// <summary>Same gate order as <see cref="CommandDispatcher"/>, without its idempotency cache.</summary>
    private static Task<CommandResult> InvokeAsync(ICommandHandler handler, AgentCommand command, CancellationToken ct)
        => handler switch
        {
            IAuthoritativeCommandExecutionGate authoritative =>
                authoritative.ExecuteAuthorizedAsync(command, (verified, cancel) => authoritative.HandleAuthorizedAsync(verified, cancel), ct),
            IReplayAwareCommandExecutionGate replayAware =>
                replayAware.ExecuteAuthorizedAsync(command, null, () => handler.HandleAsync(command, ct), ct),
            ICommandExecutionGate gated =>
                gated.ExecuteAuthorizedAsync(command, () => gated.HandleAuthorizedAsync(command, ct), ct),
            _ => handler.HandleAsync(command, ct),
        };

    /// <summary>
    /// Stores the result with a compare-and-set on <paramref name="record"/>'s state, retrying a failed write once.
    /// A record that already holds a result is returned as stored and never overwritten. Durable is false when the
    /// write failed twice: the returned record then carries the in-memory result.
    /// </summary>
    private (CommandReplayRecord Record, bool Durable) StoreResult(CommandReplayRecord record, byte[] body)
    {
        var done = record with
        {
            State = EnvelopeRecordStates.Done,
            ResultB64 = Convert.ToBase64String(body),
            ResultSha256 = CommandEnvelope.Sha256Hex(body),
            ResultSubmitted = false,
        };
        var outcome = Store.TryUpdate(done, record.State);
        if (outcome == ReplayUpdateOutcome.Failed)
            outcome = Store.TryUpdate(done, record.State);
        switch (outcome)
        {
            case ReplayUpdateOutcome.Updated:
                return (done, true);
            case ReplayUpdateOutcome.Conflict:
                _log.Warn($"Command envelope id={record.Id} result not stored: the record is no longer {record.State}.");
                return (Store.Find(record.AgentId, record.Id) ?? record, true);
            default:
                _log.Error($"Command envelope id={record.Id} result not stored durably; submitting from memory.");
                return (done, false);
        }
    }

    private void Finish(CommandReplayRecord record, bool keepInFlight = false)
    {
        if (!keepInFlight)
            ClearInFlight(record.AgentId, record.Id);
        ReleaseSlot();
    }

    private static byte[] Failed(string code, string envelopeSha256)
        => CommandEnvelope.BuildResultBody("FAILED", null, code, null, envelopeSha256);

    private static bool IsFinalRefusal(HttpStatusCode status)
        => (int)status is >= 400 and < 500 && status is not (HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests);

    private sealed record QueuedEnvelope(CommandReplayRecord Record, SignedEnvelope Envelope);
}
