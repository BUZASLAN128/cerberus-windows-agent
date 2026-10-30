using System.Net;
using System.Net.WebSockets;
using System.Text.Json;

namespace Cerberus.Agent.Core;

public sealed partial class AgentApiClient
{
    internal Func<HttpMessageInvoker>? WakeupInvokerFactory { get; set; }

    internal bool IsWakeupDiscovery(JsonElement? discovery)
        => _http.BaseAddress is not null && AgentWakeupProtocol.TryReadDiscovery(_http.BaseAddress, discovery, out _);

    /// <summary>Create the same empty-body signed GET used by the product's HTTPS agent identity.</summary>
    internal async Task<(Uri Endpoint, HttpRequestMessage Request)> BuildWakeupHandshakeAsync(
        JsonElement? discovery, CancellationToken ct)
    {
        if (_http.BaseAddress is null || !AgentWakeupProtocol.TryReadDiscovery(_http.BaseAddress, discovery, out var endpoint))
            throw new InvalidOperationException("Wakeup discovery is invalid.");

        // Bind the discovery to the current enrollment before obtaining a token or signing anything.
        var (identity, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var expectedPath = $"/api/v1/agents/{Uri.EscapeDataString(identity.AgentId)}/wakeup";
        if (!string.Equals(endpoint!.AbsolutePath, expectedPath, StringComparison.Ordinal))
            throw new InvalidOperationException("Wakeup discovery does not match the current agent.");

        var request = await BuildSignedJsonRequestAsync(HttpMethod.Get, expectedPath, string.Empty, ct).ConfigureAwait(false);
        if (!request.Headers.TryGetValues("X-Agent-Id", out var ids) ||
            !string.Equals(ids.SingleOrDefault(), identity.AgentId, StringComparison.Ordinal))
        {
            request.Dispose();
            throw new InvalidOperationException("Agent identity changed during wakeup handshake preparation.");
        }
        return (endpoint, request);
    }

    /// <summary>Maintain one hint-only connection; cancellation or an invalid frame closes it.</summary>
    internal async Task ListenForWakeupsOnceAsync(JsonElement discovery, AgentWakeupSignal signal, CancellationToken ct)
    {
        var (endpoint, request) = await BuildWakeupHandshakeAsync(discovery, ct).ConfigureAwait(false);
        using (request)
        using (var socket = new ClientWebSocket())
        using (var handler = BackendTrust.CreateHandler())
        using (var invoker = WakeupInvokerFactory?.Invoke() ?? new HttpMessageInvoker(handler, disposeHandler: false))
        using (var connection = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            handler.AllowAutoRedirect = false;
            socket.Options.CollectHttpResponseDetails = true;
            foreach (var name in new[] { "Authorization", "X-Agent-Id", "X-Nonce", "X-Timestamp", "X-Body-Hash", "X-Signature" })
            {
                if (!request.Headers.TryGetValues(name, out var values))
                    throw new InvalidOperationException("Wakeup signing header is missing.");
                socket.Options.SetRequestHeader(name, values.Single());
            }

            // Bound handshake and connection lifetime independently of server behavior.
            using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(connection.Token))
            {
                handshake.CancelAfter(TimeSpan.FromSeconds(15));
                try
                {
                    await socket.ConnectAsync(endpoint, invoker, handshake.Token).ConfigureAwait(false);
                }
                catch (WebSocketException) when (socket.HttpStatusCode == HttpStatusCode.TooManyRequests ||
                                                 (int)socket.HttpStatusCode >= 500)
                {
                    throw new WakeupRateLimitedException(WakeupRetryAfter(socket.HttpResponseHeaders));
                }
                catch (WebSocketException) when (socket.HttpStatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                {
                    throw new WakeupRejectedException();
                }
            }

            connection.CancelAfter(TimeSpan.FromMinutes(5));
            var generation = request.Options.TryGetValue(LifecycleGenerationKey, out var value) ? value : (long?)null;
            var buffer = new byte[AgentWakeupProtocol.MaxNotificationBytes + 1];
            var used = 0;
            var receive = socket.ReceiveAsync(buffer.AsMemory(used), connection.Token).AsTask();
            var check = Task.Delay(TimeSpan.FromSeconds(5), connection.Token);
            while (true)
            {
                var ready = await Task.WhenAny(receive, check).ConfigureAwait(false);
                if (ready == check)
                {
                    await check.ConfigureAwait(false);
                    await EnsureWakeupLifecycleAsync(generation, connection.Token).ConfigureAwait(false);
                    check = Task.Delay(TimeSpan.FromSeconds(5), connection.Token);
                    continue;
                }

                var message = await receive.ConfigureAwait(false);
                if (message.MessageType == WebSocketMessageType.Close)
                    return;
                if (message.MessageType != WebSocketMessageType.Text || message.Count == 0 && !message.EndOfMessage)
                    throw new InvalidOperationException("Invalid wakeup frame.");
                used += message.Count;
                if (used > AgentWakeupProtocol.MaxNotificationBytes)
                    throw new InvalidOperationException("Wakeup frame is too large.");
                if (message.EndOfMessage)
                {
                    if (!AgentWakeupProtocol.IsCommandAvailable(buffer.AsMemory(0, used)))
                        throw new InvalidOperationException("Invalid wakeup message.");
                    await EnsureWakeupLifecycleAsync(generation, connection.Token).ConfigureAwait(false);
                    signal.Signal();
                    used = 0;
                }
                receive = socket.ReceiveAsync(buffer.AsMemory(used), connection.Token).AsTask();
            }
        }
    }

    private async Task EnsureWakeupLifecycleAsync(long? generation, CancellationToken ct)
    {
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        if (_lifecycleState is null)
            return;
        var state = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        if (generation != state.Generation || state.NextAttemptUtc > DateTimeOffset.UtcNow)
            throw new AgentLifecycleDormantException(state);
    }

    private static TimeSpan WakeupRetryAfter(IReadOnlyDictionary<string, IEnumerable<string>>? headers)
    {
        if (headers is not null && headers.TryGetValue("Retry-After", out var values))
        {
            var value = values.FirstOrDefault();
            if (int.TryParse(value, out var seconds))
                return TimeSpan.FromSeconds(Math.Max(seconds, 5));
            if (DateTimeOffset.TryParse(value, out var date))
                return TimeSpan.FromSeconds(Math.Max((date - DateTimeOffset.UtcNow).TotalSeconds, 5));
        }
        return TimeSpan.FromSeconds(30);
    }
}

internal sealed class WakeupRateLimitedException(TimeSpan retryAfter) : Exception
{
    public TimeSpan RetryAfter { get; } = retryAfter;
}

internal sealed class WakeupRejectedException : Exception;
