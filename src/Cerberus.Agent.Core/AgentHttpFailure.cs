using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

public sealed record AgentHttpFailureInfo(
    HttpStatusCode StatusCode,
    string? TransportCode,
    string? DetailCode,
    string? Status,
    string? RequestId,
    TimeSpan? RetryAfter)
{
    /// <summary>
    /// Returns the most specific bounded code without exposing the response body.
    /// </summary>
    public string? Code => DetailCode ?? TransportCode;
}

public sealed class AgentHttpException : HttpRequestException
{
    public AgentHttpException(string message, AgentHttpFailureInfo failure)
        : base(message, inner: null, statusCode: failure.StatusCode)
    {
        Failure = failure;
    }

    public AgentHttpFailureInfo Failure { get; }
    public string? Code => Failure.Code;
    public string? RequestId => Failure.RequestId;
    public TimeSpan? RetryAfter => Failure.RetryAfter;
}

/// <summary>
/// Applies bounded, status-safe response handling to agent HTTP calls.
/// </summary>
public static class AgentHttpFailure
{
    // Keep error inspection below the size used by the backend's compact error
    // envelope.  The response body is never included in a failure message.
    private const int MaxErrorBodyBytes = 4096;
    private const int MaxSuccessBodyBytes = 64 * 1024;
    private const int MaxRequestIdLength = 64;
    private const int MaxCodeLength = 64;
    private const int MaxStatusLength = 64;
    private const string PayloadInvalidDataKey = "cerberus-agent-payload-invalid";
    private static readonly TimeSpan InfiniteTimeoutFallback = TimeSpan.FromSeconds(30);

    private static readonly Regex RequestIdPattern = new(
        "^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking | RegexOptions.Compiled);

    // This mirrors the Cerberus API error_contract status mapping.  A code is
    // retained only when it is the canonical code for this response status;
    // CSRF_FAILED is the sole explicit 403 override and REQUEST_FAILED is the
    // canonical fallback for statuses without a mapping.
    private static readonly IReadOnlyDictionary<int, string> ErrorCodeByStatus =
        new Dictionary<int, string>
        {
            [400] = "REQUEST_INVALID",
            [401] = "AUTH_UNAUTHORIZED",
            [403] = "AUTH_FORBIDDEN",
            [404] = "NOT_FOUND",
            [409] = "CONFLICT",
            [413] = "PAYLOAD_TOO_LARGE",
            [422] = "CONTEXT_INVALID",
            [429] = "RATE_LIMITED",
            [500] = "INTERNAL_ERROR",
            [502] = "BAD_GATEWAY",
            [503] = "SERVICE_UNAVAILABLE",
        };

    private static readonly HashSet<string> KnownTransportCodes =
        new(ErrorCodeByStatus.Values.Append("REQUEST_FAILED").Append("CSRF_FAILED"), StringComparer.Ordinal);

    /// <summary>
    /// Creates the single timeout budget shared by response-header and body reads.
    /// </summary>
    public static CancellationTokenSource CreateDeadline(HttpClient http, CancellationToken callerCt)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(callerCt);
        deadline.CancelAfter(GetContentReadTimeout(http));
        return deadline;
    }

    public static TimeSpan GetContentReadTimeout(HttpClient http)
    {
        var timeout = http.Timeout;
        return timeout != Timeout.InfiniteTimeSpan && timeout > TimeSpan.Zero
            ? timeout
            : InfiniteTimeoutFallback;
    }

    public static async Task<HttpRequestException> CreateAsync(
        string operation,
        HttpResponseMessage response,
        HttpClient http,
        CancellationToken ct,
        CancellationToken? deadlineCt = null)
    {
        var requestId = TryGetRequestId(response);
        var info = await TryReadFailureInfoAsync(response, http, ct, deadlineCt, requestId).ConfigureAwait(false);
        return CreateException(operation, info);
    }

    public static HttpRequestException CreateStatusOnly(string operation, HttpResponseMessage response)
    {
        var info = new AgentHttpFailureInfo(
            response.StatusCode,
            TransportCode: null,
            DetailCode: null,
            Status: null,
            RequestId: TryGetRequestId(response),
            RetryAfter: TryGetRetryAfter(response));
        return CreateException(operation, info);
    }

    public static async Task<string> ReadBodyAsStringAsync(
        string operation,
        HttpResponseMessage response,
        HttpClient http,
        CancellationToken ct,
        CancellationToken? deadlineCt = null)
    {
        try
        {
            var body = await ReadBoundedBodyAsync(response, http, ct, deadlineCt, MaxSuccessBodyBytes).ConfigureAwait(false);
            return Encoding.UTF8.GetString(body);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            throw CreateStatusOnly(operation, response);
        }
    }

    public static async Task<T?> ReadJsonAsync<T>(
        string operation,
        HttpResponseMessage response,
        HttpClient http,
        JsonSerializerOptions options,
        CancellationToken ct,
        CancellationToken? deadlineCt = null)
    {
        byte[] body;
        try
        {
            body = await ReadBoundedBodyAsync(response, http, ct, deadlineCt, MaxSuccessBodyBytes).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // A bounded body read can fail because the transport/deadline is
            // unavailable. Keep it status-only so retry callers do not treat
            // a temporary read outage as a protocol mismatch.
            throw CreateStatusOnly(operation, response);
        }

        try
        {
            return JsonSerializer.Deserialize<T>(body, options);
        }
        catch
        {
            var failure = CreateStatusOnly(operation, response);
            failure.Data[PayloadInvalidDataKey] = true;
            throw failure;
        }
    }

    public static bool IsPayloadInvalid(HttpRequestException exception)
        => exception.Data.Contains(PayloadInvalidDataKey);

    private static HttpRequestException CreateException(string operation, AgentHttpFailureInfo failure)
    {
        var details = new List<string>(capacity: 2);
        if (!string.IsNullOrEmpty(failure.Code))
            details.Add($"code={failure.Code}");
        if (!string.IsNullOrEmpty(failure.RequestId))
            details.Add($"request_id={failure.RequestId}");

        var suffix = details.Count == 0
            ? string.Empty
            : $" [{string.Join(", ", details)}]";

        var message = $"{operation} failed ({(int)failure.StatusCode}).{suffix}";
        // Preserve the established HttpRequestException contract for plain
        // status-only failures. Metadata-bearing failures use the typed form
        // so lifecycle/auth callers can consume only validated fields.
        return failure.Code is null &&
               failure.Status is null &&
               failure.RequestId is null &&
               failure.RetryAfter is null
            ? new HttpRequestException(message, inner: null, statusCode: failure.StatusCode)
            : new AgentHttpException(message, failure);
    }

    private static async Task<AgentHttpFailureInfo> TryReadFailureInfoAsync(
        HttpResponseMessage response,
        HttpClient http,
        CancellationToken ct,
        CancellationToken? deadlineCt,
        string? requestId)
    {
        try
        {
            var body = await ReadBoundedBodyAsync(response, http, ct, deadlineCt, MaxErrorBodyBytes).ConfigureAwait(false);
            var parsed = ParseFailureInfo(body, response.StatusCode, requestId, TryGetRetryAfter(response));
            return parsed;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Response-body reads are diagnostic-only.  Any internal deadline,
            // read, or size failure falls back to status and safe headers.
            return new AgentHttpFailureInfo(
                response.StatusCode,
                TransportCode: null,
                DetailCode: null,
                Status: null,
                RequestId: requestId,
                RetryAfter: TryGetRetryAfter(response));
        }
    }

    private static async Task<byte[]> ReadBoundedBodyAsync(
        HttpResponseMessage response,
        HttpClient http,
        CancellationToken callerCt,
        CancellationToken? deadlineCt,
        int maxBytes)
    {
        var content = response.Content;
        if (content is null)
            return Array.Empty<byte>();
        if (content.Headers.ContentLength is long contentLength && contentLength > maxBytes)
            throw new InvalidOperationException("Response body exceeds the inspection limit.");

        using var ownedDeadline = deadlineCt is null ? CreateDeadline(http, callerCt) : null;
        var readCt = deadlineCt ?? ownedDeadline!.Token;

        await using var stream = await content.ReadAsStreamAsync(readCt).ConfigureAwait(false);
        var buffer = new byte[maxBytes + 1];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), readCt).ConfigureAwait(false);
            if (read == 0)
                break;
            length += read;
        }

        // Read one extra byte so an absent or inaccurate Content-Length cannot
        // make an oversized response look parseable.
        if (length == buffer.Length)
            throw new InvalidOperationException("Response body exceeds the inspection limit.");

        return buffer.AsSpan(0, length).ToArray();
    }

    internal static AgentHttpFailureInfo ParseFailureInfo(
        ReadOnlyMemory<byte> body,
        HttpStatusCode statusCode,
        string? requestId = null,
        TimeSpan? retryAfter = null)
    {
        if (body.IsEmpty)
            return new AgentHttpFailureInfo(statusCode, null, null, null, requestId, retryAfter);

        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });

            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return new AgentHttpFailureInfo(statusCode, null, null, null, requestId, retryAfter);

            string? transportCode = null;
            string? detailCode = null;
            string? status = null;
            var seenProperties = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!seenProperties.Add(property.Name))
                    return new AgentHttpFailureInfo(statusCode, null, null, null, requestId, retryAfter);
                if (string.Equals(property.Name, "error_code", StringComparison.Ordinal))
                {
                    if (transportCode is not null || property.Value.ValueKind != JsonValueKind.String)
                        return new AgentHttpFailureInfo(statusCode, null, null, null, requestId, retryAfter);
                    transportCode = ValidateCode(property.Value.GetString());
                    continue;
                }

                if (string.Equals(property.Name, "status", StringComparison.Ordinal))
                {
                    if (property.Value.ValueKind != JsonValueKind.String)
                        continue;
                    status = ValidateStatus(property.Value.GetString());
                    continue;
                }

                if (!string.Equals(property.Name, "detail", StringComparison.Ordinal) ||
                    property.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var seenDetailProperties = new HashSet<string>(StringComparer.Ordinal);
                foreach (var detailProperty in property.Value.EnumerateObject())
                {
                    if (!seenDetailProperties.Add(detailProperty.Name))
                        return new AgentHttpFailureInfo(statusCode, null, null, null, requestId, retryAfter);
                    if (!string.Equals(detailProperty.Name, "code", StringComparison.Ordinal))
                        continue;
                    if (detailCode is not null || detailProperty.Value.ValueKind != JsonValueKind.String)
                        return new AgentHttpFailureInfo(statusCode, null, null, null, requestId, retryAfter);
                    detailCode = ValidateCode(detailProperty.Value.GetString());
                }
            }

            if (transportCode is not null &&
                !KnownTransportCodes.Contains(transportCode) &&
                !AgentLifecycleStatePolicy.IsProtocolOrConfigCode(transportCode))
            {
                transportCode = null;
            }

            if (string.Equals(transportCode, "CSRF_FAILED", StringComparison.Ordinal) &&
                statusCode != HttpStatusCode.Forbidden)
            {
                transportCode = null;
            }

            if (transportCode is not null &&
                ErrorCodeByStatus.TryGetValue((int)statusCode, out var expectedCode) &&
                !string.Equals(transportCode, expectedCode, StringComparison.Ordinal) &&
                !AgentLifecycleStatePolicy.IsProtocolOrConfigCode(transportCode))
            {
                transportCode = null;
            }

            // Lifecycle authority is the canonical 401 envelope only. A code
            // echoed by a proxy, HTML/error response or wrong status is not a revoke.
            if ((AgentLifecycleStatePolicy.IsTerminalCode(detailCode) ||
                 detailCode == AgentLifecycleStatePolicy.AgentReenrollRequiredCode) &&
                (statusCode != HttpStatusCode.Unauthorized || transportCode != "AUTH_UNAUTHORIZED"))
                detailCode = null;

            return new AgentHttpFailureInfo(statusCode, transportCode, detailCode, status, requestId, retryAfter);
        }
        catch
        {
            return new AgentHttpFailureInfo(statusCode, null, null, null, requestId, retryAfter);
        }
    }

    private static string? ValidateCode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxCodeLength)
            return null;
        foreach (var ch in value)
        {
            if (!(char.IsAsciiLetterOrDigit(ch) || ch is '_' or '-' or '.' or ':'))
                return null;
        }
        return value;
    }

    private static string? ValidateStatus(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxStatusLength)
            return null;
        foreach (var ch in value)
        {
            if (!(char.IsAsciiLetterOrDigit(ch) || ch is '_' or '-' or '.' or ':'))
                return null;
        }
        return value;
    }

    private static TimeSpan? TryGetRetryAfter(HttpResponseMessage response)
    {
        try
        {
            if (!response.Headers.TryGetValues("Retry-After", out var values))
                return null;

            using var enumerator = values.GetEnumerator();
            if (!enumerator.MoveNext())
                return null;
            var raw = enumerator.Current?.Trim();
            if (enumerator.MoveNext())
                return null;
            if (string.IsNullOrWhiteSpace(raw) || raw.Length > 64)
                return null;

            if (int.TryParse(raw, out var seconds) && seconds >= 0)
                return TimeSpan.FromSeconds(Math.Clamp(seconds, 5, 3600));

            if (DateTimeOffset.TryParse(raw, out var retryAt))
            {
                var delay = retryAt - DateTimeOffset.UtcNow;
                return TimeSpan.FromSeconds(Math.Clamp(delay.TotalSeconds, 5, 3600));
            }
        }
        catch
        {
            // Header parsing is diagnostic-only and must never fail the request.
        }
        return null;
    }

    private static string? TryGetRequestId(HttpResponseMessage response)
    {
        try
        {
            if (!response.Headers.TryGetValues("X-Request-ID", out var values))
                return null;

            using var enumerator = values.GetEnumerator();
            if (!enumerator.MoveNext())
                return null;
            var value = enumerator.Current;
            if (enumerator.MoveNext())
                return null;

            return IsValidRequestId(value) ? value : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsValidRequestId(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaxRequestIdLength)
            return false;

        return RequestIdPattern.IsMatch(value);
    }
}
