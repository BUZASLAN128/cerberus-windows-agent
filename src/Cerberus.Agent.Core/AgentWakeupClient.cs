using System.Security.Cryptography;
using System.Text.Json;

namespace Cerberus.Agent.Core;

/// <summary>Owns one optional notification connection; HTTPS remains the source of commands.</summary>
public sealed class AgentWakeupClient : IAsyncDisposable
{
    private readonly AgentApiClient _api;
    private readonly AgentWakeupSignal _signal;
    private readonly IAgentLogger _log;
    private readonly Func<JsonElement, AgentWakeupSignal, CancellationToken, Task> _listen;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private CancellationTokenSource? _connection;
    private Task? _runner;
    private string? _discoveryKey;
    private DateTimeOffset _notBefore;

    public AgentWakeupClient(AgentApiClient api, AgentWakeupSignal signal, IAgentLogger? log = null)
        : this(api, signal, api.ListenForWakeupsOnceAsync, log)
    {
    }

    internal AgentWakeupClient(AgentApiClient api, AgentWakeupSignal signal,
        Func<JsonElement, AgentWakeupSignal, CancellationToken, Task> listen, IAgentLogger? log = null)
    {
        _api = api;
        _signal = signal;
        _listen = listen;
        _log = log ?? NullAgentLogger.Instance;
    }

    /// <summary>Only a fresh successful heartbeat can enable or change discovery.</summary>
    public async Task ConfigureAsync(JsonElement? discovery, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (discovery is not { ValueKind: JsonValueKind.Object } value || !_api.IsWakeupDiscovery(discovery))
            {
                await StopCoreAsync().ConfigureAwait(false);
                return;
            }
            var key = value.GetRawText();
            if (_runner is { IsCompleted: false } && string.Equals(key, _discoveryKey, StringComparison.Ordinal))
                return;
            await StopCoreAsync().ConfigureAwait(false);
            _discoveryKey = key;
            _connection = new CancellationTokenSource();
            _runner = RunAsync(value.Clone(), _connection.Token);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { await StopCoreAsync().ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    private async Task StopCoreAsync()
    {
        var source = _connection;
        var runner = _runner;
        _connection = null;
        _runner = null;
        _discoveryKey = null;
        if (source is null)
        {
            _signal.Clear();
            return;
        }
        source.Cancel();
        try { if (runner is not null) await runner.ConfigureAwait(false); }
        catch (OperationCanceledException) when (source.IsCancellationRequested) { }
        catch (Exception ex) { _log.Warn($"Wakeup task stopped: {ex.GetType().Name}."); }
        finally { source.Dispose(); _signal.Clear(); }
    }

    private async Task RunAsync(JsonElement discovery, CancellationToken ct)
    {
        var failures = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var remaining = _notBefore - DateTimeOffset.UtcNow;
                if (remaining > TimeSpan.Zero)
                {
                    // Task.Delay cannot represent very large server Retry-After values.
                    // Recheck the same deadline in bounded increments without reconnecting.
                    await Task.Delay(remaining > TimeSpan.FromHours(1) ? TimeSpan.FromHours(1) : remaining, ct)
                        .ConfigureAwait(false);
                    continue;
                }
                await _listen(discovery, _signal, ct).ConfigureAwait(false);
                failures = 0;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (AgentLifecycleDormantException)
            {
                return;
            }
            catch (WakeupRejectedException)
            {
                // Some ASGI servers cannot forward a pre-upgrade 429 and expose it
                // as 403 without Retry-After. Retain the server's maximum bucket wait.
                _notBefore = DateTimeOffset.UtcNow.AddMinutes(10);
                return;
            }
            catch (InvalidOperationException)
            {
                return;
            }
            catch (WakeupRateLimitedException rateLimit)
            {
                // Preserve this deadline even if a later heartbeat reconfigures the connection.
                var now = DateTimeOffset.UtcNow;
                _notBefore = rateLimit.RetryAfter >= DateTimeOffset.MaxValue - now
                    ? DateTimeOffset.MaxValue
                    : now.Add(rateLimit.RetryAfter);
                failures = 0;
            }
            catch (Exception ex)
            {
                _log.Warn($"Wakeup connection unavailable: {ex.GetType().Name}.");
                failures = Math.Min(failures + 1, 6);
            }

            // Spread fleet reconnects over a wider window after disconnect or failure.
            var cap = Math.Min(300, 30 * (1 << Math.Max(0, failures - 1)));
            var delay = TimeSpan.FromSeconds(RandomNumberGenerator.GetInt32(1, cap + 1));
            try { await Task.Delay(delay, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync(CancellationToken.None).ConfigureAwait(false);
        _gate.Dispose();
    }
}
