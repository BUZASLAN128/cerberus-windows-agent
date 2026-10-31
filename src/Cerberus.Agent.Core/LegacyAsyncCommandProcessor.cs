using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace Cerberus.Agent.Core;

/// <summary>
/// Lease-bound generic legacy commands execute away from heartbeat. This processor is only
/// advertised to a server that can keep an expired lease terminal and accept unknown results.
/// Managed local-user and AD commands remain on their existing authority path.
/// </summary>
public sealed class LegacyAsyncCommandProcessor : IHeartbeatCommandProcessor, IAsyncDisposable
{
    public const string Capability = "agent.legacy-async.v1";
    public const int MaxPending = 8;
    private const int MaxLegacyResultBytes = 60 * 1024; // backend limit is 64 KiB
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    // A supervisor can replace a worker while a handler ignores cancellation. The
    // permit must survive worker replacement for the lifetime of this process.
    private static readonly SemaphoreSlim HandlerGate = new(1, 1);
    private static readonly HashSet<string> Types = new(StringComparer.Ordinal)
    {
        "tailscale.ensure_connected", "agent.health.snapshot", "agent.rdp.quick_test",
        "agent.diagnostic_bundle.collect", "agent.update.request",
    };

    private readonly AgentApiClient _api;
    private readonly CommandDispatcher _dispatcher;
    private readonly IHeartbeatCommandProcessor _legacy;
    private readonly CommandReplayStore _store;
    private readonly Func<CancellationToken, Task<string>> _currentAgentId;
    private readonly IAgentLogger _log;
    private readonly AgentRetryGate _resultRetry;
    private readonly ConcurrentQueue<(AgentCommand Command, CommandReplayRecord Record)> _pending = new();
    private readonly ConcurrentDictionary<(string AgentId, string Id), byte> _inFlight = new();
    private readonly SemaphoreSlim _wake = new(0);
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _worker;
    private int _slots;
    private int _disposed;

    public LegacyAsyncCommandProcessor(AgentApiClient api, CommandDispatcher dispatcher,
        IHeartbeatCommandProcessor legacy, CommandReplayStore store,
        Func<CancellationToken, Task<string>> currentAgentId, IAgentLogger? log = null, TimeProvider? time = null)
    {
        _api = api;
        _dispatcher = dispatcher;
        _legacy = legacy;
        _store = store;
        _currentAgentId = currentAgentId;
        _log = log ?? NullAgentLogger.Instance;
        _resultRetry = new AgentRetryGate(time ?? TimeProvider.System);
        _worker = Task.Run(() => RunAsync(_stop.Token));
        _wake.Release(); // recover a previous process before the first heartbeat
    }

    public async Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct)
    {
        _stop.Token.ThrowIfCancellationRequested();
        var inline = new List<AgentCommand>();
        var agentId = await _currentAgentId(ct).ConfigureAwait(false);
        foreach (var command in commands)
        {
            if (command is null || !Types.Contains(command.Type))
            {
                inline.Add(command!);
                continue;
            }
            // Never let the compatibility path bypass an unavailable/reset replay boundary.
            if (!_store.AllowsLegacyAgent(agentId) || !_store.IsAvailable || _store.ResetAt != 0)
            {
                _log.Warn($"Async command id={LogId(command.Id)} not started: durable replay state is unavailable or reset; recovery requires verified re-enrollment with a new agent identity.");
                continue;
            }
            if (string.IsNullOrWhiteSpace(command.LeaseId))
            {
                inline.Add(command);
                continue;
            }
            if (!Guid.TryParseExact(command.Id, "D", out _) || !Guid.TryParseExact(command.LeaseId, "D", out _)
                || string.IsNullOrWhiteSpace(command.IdempotencyKey) || command.IdempotencyKey.Length > 255)
            {
                _log.Warn("Async command not started: lease identity is invalid.");
                continue;
            }
            if (command.LeaseExpiresAtUnix is not > 1 || command.SafeLeaseDeadlineTimestamp is not { } deadline
                || System.Diagnostics.Stopwatch.GetTimestamp() >= deadline)
            {
                _log.Warn($"Async command id={LogId(command.Id)} not started: lease timing is invalid or expired.");
                continue;
            }

            if (!TryAcquireSlot())
            {
                _log.Warn($"Async command id={LogId(command.Id)} not started: execution queue is full.");
                continue;
            }
            var key = (agentId, command.Id);
            if (!_inFlight.TryAdd(key, 0)) { ReleaseSlot(); continue; }
            try
            {
                var hash = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(command, Json))).ToLowerInvariant();
                var existing = _store.Find(agentId, command.Id);
                if (existing is not null)
                {
                    if (existing.EnvelopeSha256 != hash || existing.Nonce != command.LeaseId)
                        _log.Warn($"Async command id={LogId(command.Id)} conflicts with durable evidence.");
                    _inFlight.TryRemove(key, out _);
                    ReleaseSlot();
                    continue;
                }
                var expires = command.LeaseExpiresAtUnix.Value;
                var record = new CommandReplayRecord(agentId, command.Id, hash, command.LeaseId!, command.Type,
                    Math.Max(1, expires - 86400), expires, EnvelopeRecordStates.Reserved, null, null, false);
                if (_store.TryReserve(record) != ReplayReserveOutcome.Reserved)
                {
                    _inFlight.TryRemove(key, out _);
                    ReleaseSlot();
                    continue;
                }
                _pending.Enqueue((command, record));
                _wake.Release();
            }
            catch
            {
                _inFlight.TryRemove(key, out _);
                ReleaseSlot();
                throw;
            }
        }
        if (inline.Count > 0)
            await _legacy.ProcessAsync(inline, ct).ConfigureAwait(false);
        SignalOutbox();
    }

    public void SignalOutbox() => _wake.Release();
    public void CancelAll() => _stop.Cancel();
    internal long OutboxNotBefore => _resultRetry.NotBefore;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _stop.Cancel();
        try { await _worker.ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        _stop.Dispose();
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await _wake.WaitAsync(ct).ConfigureAwait(false);
                while (_pending.TryDequeue(out var item))
                {
                    await RunOneAsync(item.Command, item.Record, ct).ConfigureAwait(false);
                    await DrainAsync(ct).ConfigureAwait(false);
                }
                await DrainAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception ex) { _log.Warn($"Async command queue unavailable: {ex.GetType().Name}."); }
        }
    }

    private async Task RunOneAsync(AgentCommand command, CommandReplayRecord record, CancellationToken ct)
    {
        try
        {
            if (await _currentAgentId(ct).ConfigureAwait(false) != record.AgentId) return;
            var nowTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            if (command.SafeLeaseDeadlineTimestamp is not { } deadline || nowTicks >= deadline)
            {
                StoreResult(record, Unknown());
                return;
            }
            var started = record with { State = EnvelopeRecordStates.Started };
            if (_store.TryUpdate(started, EnvelopeRecordStates.Reserved) != ReplayUpdateOutcome.Updated) return;
            nowTicks = System.Diagnostics.Stopwatch.GetTimestamp();
            if (nowTicks >= deadline)
            {
                StoreResult(started, Unknown());
                return;
            }
            var duration = command.Type == "agent.update.request" ? TimeSpan.FromMinutes(20) : TimeSpan.FromSeconds(120);
            var leaseRemaining = System.Diagnostics.Stopwatch.GetElapsedTime(nowTicks, deadline);
            if (leaseRemaining < duration) duration = leaseRemaining;
            using var timeout = new CancellationTokenSource(duration);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
            CommandResult result;
            try
            {
                // A handler can block before returning its Task. Keep even that work off
                // the queue loop so cancellation and shutdown remain observable.
                var invocation = Task.Run(() => InvokeBoundedAsync(command, linked.Token), CancellationToken.None);
                _ = invocation.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                result = await invocation.WaitAsync(linked.Token).ConfigureAwait(false);
                if (timeout.IsCancellationRequested || IsIndeterminateFailure(result)) result = Unknown();
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { result = Unknown(); }
            catch (Exception ex) when (ex is not OperationCanceledException) { result = Unknown(); }
            if (ct.IsCancellationRequested) return; // started record is recovered as unknown
            StoreResult(started, result);
        }
        finally
        {
            _inFlight.TryRemove((record.AgentId, record.Id), out _);
            ReleaseSlot();
        }
    }

    private async Task<CommandResult> InvokeBoundedAsync(AgentCommand command, CancellationToken ct)
    {
        await HandlerGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ct.ThrowIfCancellationRequested();
            if (command.SafeLeaseDeadlineTimestamp is not { } deadline || System.Diagnostics.Stopwatch.GetTimestamp() >= deadline)
                return Unknown();
            return await _dispatcher.DispatchAsync(command, ct).ConfigureAwait(false);
        }
        finally { HandlerGate.Release(); }
    }

    private void StoreResult(CommandReplayRecord record, CommandResult result)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(result, Json);
        if (bytes.Length > MaxLegacyResultBytes)
            bytes = JsonSerializer.SerializeToUtf8Bytes(Unknown(), Json);
        var done = record with { State = EnvelopeRecordStates.Done, ResultB64 = Convert.ToBase64String(bytes),
            ResultSha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() };
        if (_store.TryUpdate(done, record.State) != ReplayUpdateOutcome.Updated)
            _log.Warn($"Async command id={LogId(record.Id)} result could not be persisted; it will be reported unknown.");
    }

    private async Task DrainAsync(CancellationToken ct)
    {
        if (!_resultRetry.CanTry) return;
        if (!_store.IsAvailable || _store.ResetAt != 0) return;
        var agent = await _currentAgentId(ct).ConfigureAwait(false);
        if (!_store.AllowsLegacyAgent(agent)) return;
        // Retained, already-submitted records still protect against replay but are
        // not outbox work. Filter before bounding the batch so they cannot starve
        // newer results or records that must be recovered after a restart.
        foreach (var record in _store.Records(agent).Where(r =>
            !_inFlight.ContainsKey((r.AgentId, r.Id)) &&
            (r.State is EnvelopeRecordStates.Reserved or EnvelopeRecordStates.Started ||
             r.State == EnvelopeRecordStates.Done && !r.ResultSubmitted && r.ResultB64 is not null)).Take(16))
        {
            ct.ThrowIfCancellationRequested();
            var current = record;
            if (current.State is EnvelopeRecordStates.Reserved or EnvelopeRecordStates.Started)
            {
                StoreResult(current, Unknown());
                current = _store.Find(agent, current.Id) ?? current;
            }
            if (current.State != EnvelopeRecordStates.Done || current.ResultSubmitted || current.ResultB64 is null) continue;
            var result = JsonSerializer.Deserialize<CommandResult>(Convert.FromBase64String(current.ResultB64), Json);
            if (result is null || await _currentAgentId(ct).ConfigureAwait(false) != current.AgentId) continue;
            var command = new AgentCommand(current.Id, current.Type, current.Id, new { }, current.Nonce);
            try { await _api.SubmitCommandResultAsync(command, result, ct).ConfigureAwait(false); }
            catch (HttpRequestException ex) when (ex.StatusCode is { } status && IsFinalRefusal(status))
            { _log.Warn($"Async command id={LogId(current.Id)} result refused with HTTP {(int)status}."); }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                _resultRetry.Failed(ex);
                _log.Warn($"Async command id={LogId(current.Id)} result retained: {ex.GetType().Name}.");
                return;
            }
            _resultRetry.Succeeded();
            _store.TryUpdate(current with { ResultSubmitted = true }, EnvelopeRecordStates.Done);
        }
    }

    private static bool IsIndeterminateFailure(CommandResult result)
    {
        if (result.Status != "FAILED" || result.PostVerify is null) return false;
        var detail = JsonSerializer.SerializeToElement(result.PostVerify, Json);
        return detail.ValueKind == JsonValueKind.Object && detail.TryGetProperty("code", out var code)
               && code.ValueKind == JsonValueKind.String && code.GetString() is "command_handler_exception" or "command_timeout";
    }

    private static CommandResult Unknown() => new("OUTCOME_UNKNOWN", null, null, null, null);
    private static string LogId(string id) => Guid.TryParse(id, out var value) ? value.ToString("D") : "invalid";
    private static bool IsFinalRefusal(HttpStatusCode status)
        => (int)status is >= 400 and < 500 && status is not (HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests);
    private bool TryAcquireSlot()
    {
        while (true)
        {
            var value = Volatile.Read(ref _slots);
            if (value >= MaxPending) return false;
            if (Interlocked.CompareExchange(ref _slots, value + 1, value) == value) return true;
        }
    }
    private void ReleaseSlot() => Interlocked.Decrement(ref _slots);
}
