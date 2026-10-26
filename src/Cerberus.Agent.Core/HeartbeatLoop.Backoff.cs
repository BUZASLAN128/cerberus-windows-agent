using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

public sealed partial class HeartbeatLoop
{
    public static TimeSpan CalculateErrorDelay(TimeSpan minDelay, TimeSpan maxDelay, int consecutiveFailures)
    {
        if (minDelay <= TimeSpan.Zero)
            minDelay = TimeSpan.FromSeconds(10);
        if (maxDelay < minDelay)
            maxDelay = minDelay;

        var multiplier = Math.Pow(2, Math.Clamp(consecutiveFailures - 1, 0, 12));
        var ticks = minDelay.Ticks * multiplier;
        if (ticks >= maxDelay.Ticks)
            return maxDelay;
        return TimeSpan.FromTicks((long)ticks);
    }

    private async Task<bool> WaitForLifecycleGateAsync(CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork)
            return true;

        var snapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        if (!AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State) || !snapshot.QuiescenceComplete)
        {
            _log.Warn($"Heartbeat network paused by lifecycle state={snapshot.State}.");
            return false;
        }

        var nextAttempt = snapshot.NextAttemptUtc;
        if (nextAttempt is null || nextAttempt <= DateTimeOffset.UtcNow)
            return true;

        var remaining = nextAttempt.Value - DateTimeOffset.UtcNow;
        _log.Info($"Heartbeat retry deferred until {nextAttempt.Value:O}.");
        var resetRequested = await DelayForErrorBackoffAsync(remaining, ct).ConfigureAwait(false);
        if (resetRequested)
            await ClearPersistedRetryAsync(ct).ConfigureAwait(false);
        return !ct.IsCancellationRequested;
    }

    private async Task<bool> StopForPersistedLifecycleAsync(CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork)
            return false;

        var snapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        return !AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State);
    }

    private async Task ClearPersistedRetryAsync(CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork)
            return;

        var snapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        if (snapshot.NextAttemptUtc is not null)
        {
            await _lifecycleState.TrySaveAsync(
                AgentLifecycleStatePolicy.Normalize(snapshot with
                {
                    NextAttemptUtc = null,
                    TransientFailureCount = 0,
                    UpdatedAtUtc = DateTimeOffset.UtcNow,
                }),
                snapshot.Revision, ct).ConfigureAwait(false);
        }
    }

    private async Task PersistRetryAsync(TimeSpan delay, CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork)
            return;

        var snapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        if (!AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State))
            return;

        await _lifecycleState.TrySaveAsync(
            AgentLifecycleStatePolicy.Normalize(snapshot with
            {
                NextAttemptUtc = DateTimeOffset.UtcNow.Add(delay),
                TransientFailureCount = Math.Min(30, snapshot.TransientFailureCount + 1),
                UpdatedAtUtc = DateTimeOffset.UtcNow,
            }),
                snapshot.Revision, ct).ConfigureAwait(false);
    }

    private async Task RecordTransientLifecycleFailureAsync(Exception exception, CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork ||
            !TryGetTransientFailure(exception, out var reasonCode, out var requestId))
        {
            return;
        }

        var controller = new AgentLifecycleController(_lifecycleState, log: _log);
        await controller.RecordTransientFailureAsync(reasonCode, requestId, ct).ConfigureAwait(false);
    }

    private static bool TryGetTransientFailure(
        Exception exception,
        out string reasonCode,
        out string? requestId)
    {
        requestId = null;
        if (exception is AgentHttpException typed)
        {
            requestId = typed.RequestId;
            if (!AgentLifecycleStatePolicy.IsTransientHttpStatus(typed.Failure.StatusCode))
            {
                reasonCode = string.Empty;
                return false;
            }

            reasonCode = TransientReason(typed.Failure.StatusCode);
            return true;
        }

        if (exception is HttpRequestException request)
        {
            if (request.StatusCode is { } statusCode)
            {
                if (!AgentLifecycleStatePolicy.IsTransientHttpStatus(statusCode))
                {
                    reasonCode = string.Empty;
                    return false;
                }

                reasonCode = TransientReason(statusCode);
                return true;
            }

            reasonCode = "network_transient";
            return true;
        }

        if (exception is TimeoutException || exception is TaskCanceledException ||
            exception is OperationCanceledException)
        {
            reasonCode = "request_timeout";
            return true;
        }

        reasonCode = string.Empty;
        return false;
    }

    private static string TransientReason(System.Net.HttpStatusCode statusCode)
        => statusCode switch
        {
            System.Net.HttpStatusCode.RequestTimeout => "request_timeout",
            System.Net.HttpStatusCode.TooManyRequests => "rate_limited",
            _ when (int)statusCode is >= 500 and <= 599 => "server_unavailable",
            _ => "network_transient",
        };

    private TimeSpan CalculateRetryDelay(Exception exception, int consecutiveFailures)
    {
        if (exception is AgentHttpException rateLimit &&
            (rateLimit.RetryAfter is not null || rateLimit.Failure.StatusCode == System.Net.HttpStatusCode.TooManyRequests))
        {
            var retryAfter = rateLimit.RetryAfter ?? TimeSpan.FromSeconds(5);
            retryAfter = TimeSpan.FromSeconds(Math.Clamp(retryAfter.TotalSeconds, 5, 3600));
            var jitterSeconds = RandomNumberGenerator.GetInt32(1, Math.Max(2, (int)Math.Ceiling(retryAfter.TotalSeconds * 0.20) + 1));
            return retryAfter.Add(TimeSpan.FromSeconds(jitterSeconds));
        }

        var cap = TimeSpan.FromMinutes(15);
        var baseDelay = _minDelayOnError <= TimeSpan.Zero ? TimeSpan.FromSeconds(10) : _minDelayOnError;
        if (_lifecycleState is not null && baseDelay < TimeSpan.FromSeconds(10))
            baseDelay = TimeSpan.FromSeconds(10);
        var exponential = TimeSpan.FromTicks(Math.Min(
            cap.Ticks,
            baseDelay.Ticks * (long)Math.Pow(2, Math.Clamp(consecutiveFailures - 1, 0, 20))));
        var upperSeconds = Math.Max(1, (int)Math.Min(int.MaxValue, Math.Ceiling(exponential.TotalSeconds)));
        var jitteredSeconds = RandomNumberGenerator.GetInt32(1, upperSeconds + 1);
        return TimeSpan.FromSeconds(jitteredSeconds);
    }

    private static async Task WaitUntilCancellationAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }

    private static string FormatDelay(TimeSpan delay)
        => delay >= TimeSpan.FromMinutes(1)
            ? $"{Math.Ceiling(delay.TotalMinutes):0}m"
            : $"{Math.Ceiling(delay.TotalSeconds):0}s";

    private async Task<bool> DelayForErrorBackoffAsync(TimeSpan delay, CancellationToken ct)
    {
        if (_backoffResetRequested is null)
        {
            await Task.Delay(delay, ct).ConfigureAwait(false);
            return false;
        }

        var deadline = DateTimeOffset.UtcNow.Add(delay);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (await ConsumeBackoffResetRequestAsync(ct).ConfigureAwait(false))
                return true;

            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
                break;

            await Task.Delay(remaining < TimeSpan.FromSeconds(2) ? remaining : TimeSpan.FromSeconds(2), ct)
                .ConfigureAwait(false);
        }

        return await ConsumeBackoffResetRequestAsync(ct).ConfigureAwait(false);
    }

    private async Task<bool> ConsumeBackoffResetRequestAsync(CancellationToken ct)
    {
        try
        {
            return _backoffResetRequested is not null &&
                   await _backoffResetRequested(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.Warn($"Heartbeat retry backoff reset check failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Resolves the snapshot interval (0 = profile default, otherwise clamped), jitters it by +/-20%,
    /// then clamps again so the result stays within the profile bounds.
    /// </summary>
    internal static int SnapshotDelayWithJitter(AgentTimingPolicy timing, int serverSeconds)
        => timing.SnapshotDelaySeconds(ApplyJitter(timing.SnapshotDelaySeconds(serverSeconds), 0.20));

    private static int ApplyJitter(int seconds, double pct)
    {
        var baseSec = Math.Max(1, seconds);
        var delta = (int)Math.Ceiling(baseSec * pct);
        var off = RandomNumberGenerator.GetInt32(-delta, delta + 1);
        return Math.Max(1, baseSec + off);
    }
}
