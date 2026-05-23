namespace Cerberus.Agent.Core;

/// <summary>
/// Simple retry helper with exponential backoff.
/// </summary>
public static class RetryHelper
{
    private const int DefaultMaxRetries = 3;
    private const int DefaultBaseDelayMs = 1000;

    /// <summary>
    /// Executes an async function with exponential backoff retry.
    /// </summary>
    public static async Task<T> WithRetryAsync<T>(
        Func<Task<T>> action,
        int maxRetries = DefaultMaxRetries,
        int baseDelayMs = DefaultBaseDelayMs,
        Func<Exception, bool>? shouldRetry = null,
        IAgentLogger? log = null,
        CancellationToken ct = default)
    {
        shouldRetry ??= IsTransientError;

        for (var attempt = 0; attempt <= maxRetries; attempt++)
        {
            try
            {
                return await action();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (attempt < maxRetries && shouldRetry(ex))
            {
                var delay = CalculateDelay(attempt, baseDelayMs);
                log?.Warn($"Retry {attempt + 1}/{maxRetries}: {ex.GetType().Name}: {ex.Message}. Waiting {delay}ms...");
                await Task.Delay(delay, ct);
            }
        }

        // This should never be reached, but compiler needs it
        throw new InvalidOperationException("Retry logic error.");
    }

    /// <summary>
    /// Executes an async action with retry (no return value).
    /// </summary>
    public static async Task WithRetryAsync(
        Func<Task> action,
        int maxRetries = DefaultMaxRetries,
        int baseDelayMs = DefaultBaseDelayMs,
        Func<Exception, bool>? shouldRetry = null,
        IAgentLogger? log = null,
        CancellationToken ct = default)
    {
        await WithRetryAsync(async () =>
        {
            await action();
            return true;
        }, maxRetries, baseDelayMs, shouldRetry, log, ct);
    }

    private static int CalculateDelay(int attempt, int baseDelayMs)
    {
        // Exponential backoff: 1s, 2s, 4s...
        var delay = baseDelayMs * (1 << attempt);
        // Add jitter: +/- 25%
        var jitter = Random.Shared.Next(-delay / 4, delay / 4 + 1);
        return Math.Max(100, delay + jitter);
    }

    private static bool IsTransientError(Exception ex)
    {
        // Retry transport failures, timeouts, and server-side outages. Rate limits are
        // handled by the caller so Retry-After/backoff policy stays endpoint-specific.
        return ex switch
        {
            HttpRequestException { StatusCode: null } => true,
            HttpRequestException hre => IsRetryableStatusCode(hre),
            TaskCanceledException => true,
            TimeoutException => true,
            _ => false,
        };
    }

    private static bool IsRetryableStatusCode(HttpRequestException ex)
    {
        return ex.StatusCode is System.Net.HttpStatusCode.InternalServerError
            or System.Net.HttpStatusCode.BadGateway
            or System.Net.HttpStatusCode.ServiceUnavailable
            or System.Net.HttpStatusCode.GatewayTimeout;
    }
}
