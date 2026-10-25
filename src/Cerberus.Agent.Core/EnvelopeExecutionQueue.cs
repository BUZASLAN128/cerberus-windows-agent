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
    private readonly SemaphoreSlim _signal = new(0);
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
            Finish(dropped.Record);
    }

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
        try
        {
            var started = record with { State = EnvelopeRecordStates.Started };
            if (!Store.TryUpdate(started))
            {
                _log.Error($"Command envelope id={record.Id} not started: replay store write failed.");
                return;
            }

            var body = await ExecuteAsync(envelope, ct).ConfigureAwait(false);
            StoreResult(started, body);
        }
        finally
        {
            ClearInFlight(record.AgentId, record.Id);
        }
    }

    /// <summary>A <c>started</c> record from an earlier process: report OUTCOME_UNKNOWN once, never run again.</summary>
    internal CommandReplayRecord RecoverOrphan(CommandReplayRecord record)
    {
        var body = CommandEnvelope.BuildResultBody(OutcomeUnknown, null, null, null, record.EnvelopeSha256);
        _log.Warn($"Command envelope id={record.Id} was interrupted; reporting {OutcomeUnknown}.");
        return StoreResult(record, body);
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
        try
        {
            var current = await _currentAgentId(linked.Token).ConfigureAwait(false);
            var stored = Store.Find(record.AgentId, record.Id);
            if (!string.Equals(current, record.AgentId, StringComparison.Ordinal)
                || stored?.State != EnvelopeRecordStates.Reserved)
            {
                _log.Warn($"Command envelope id={record.Id} dropped before start: agent id or record changed.");
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
                stored = stored with { State = EnvelopeRecordStates.Started };
                if (!Store.TryUpdate(stored))
                {
                    _log.Error($"Command envelope id={record.Id} not started: replay store write failed.");
                    return;
                }

                body = await ExecuteAsync(envelope, linked.Token).ConfigureAwait(false);
            }

            var done = StoreResult(stored, body);
            await SubmitAsync(done, linked.Token).ConfigureAwait(false);
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
            Finish(record);
        }
    }

    private async Task DrainOutboxAsync(CancellationToken stop)
    {
        var agentId = await _currentAgentId(stop).ConfigureAwait(false);
        foreach (var orphan in Store.Records(agentId)
                     .Where(r => r.State == EnvelopeRecordStates.Started && !IsInFlight(r.AgentId, r.Id)))
            RecoverOrphan(orphan);

        var pending = Store.Records(agentId)
            .Where(r => r.State == EnvelopeRecordStates.Done && !r.ResultSubmitted && r.ResultB64 is not null
                        && !IsInFlight(r.AgentId, r.Id))
            .Take(OutboxPerCycle)
            .ToList();
        foreach (var record in pending)
        {
            stop.ThrowIfCancellationRequested();
            await SubmitAsync(record, stop).ConfigureAwait(false);
        }
    }

    /// <summary>POSTs the stored result bytes. Retries stop on 2xx or a 4xx other than 408/429.</summary>
    private async Task SubmitAsync(CommandReplayRecord record, CancellationToken ct)
    {
        if (record.ResultB64 is null || record.ResultSubmitted)
            return;

        try
        {
            await _api.SubmitEnvelopeResultAsync(record.AgentId, record.Id, Convert.FromBase64String(record.ResultB64), ct)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException ex) when (ex.StatusCode is { } status && IsFinalRefusal(status))
        {
            _log.Warn($"Command envelope id={record.Id} result refused with HTTP {(int)status}; not retried.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _log.Warn($"Command envelope id={record.Id} result not delivered: {ex.GetType().Name}; kept in the outbox.");
            return;
        }

        if (!Store.TryUpdate(record with { ResultSubmitted = true }))
            _log.Warn($"Command envelope id={record.Id} result delivered; replay store not updated.");
        if (_handlers.TryGetValue(record.Type, out var handler) && handler is IEnvelopeResultFollowUp followUp)
            await followUp.OnResultFinalAsync(record.AgentId, record.Id, ct).ConfigureAwait(false);
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

    private CommandReplayRecord StoreResult(CommandReplayRecord record, byte[] body)
    {
        var done = record with
        {
            State = EnvelopeRecordStates.Done,
            ResultB64 = Convert.ToBase64String(body),
            ResultSha256 = CommandEnvelope.Sha256Hex(body),
            ResultSubmitted = false,
        };
        if (!Store.TryUpdate(done))
            _log.Error($"Command envelope id={record.Id} result not stored durably; submitting from memory.");
        return done;
    }

    private void Finish(CommandReplayRecord record)
    {
        ClearInFlight(record.AgentId, record.Id);
        ReleaseSlot();
    }

    private static byte[] Failed(string code, string envelopeSha256)
        => CommandEnvelope.BuildResultBody("FAILED", null, code, null, envelopeSha256);

    private static bool IsFinalRefusal(HttpStatusCode status)
        => (int)status is >= 400 and < 500 && status is not (HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests);

    private sealed record QueuedEnvelope(CommandReplayRecord Record, SignedEnvelope Envelope);
}
