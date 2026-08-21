using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

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
        var code = await TryReadTransportCodeAsync(response, http, ct, deadlineCt).ConfigureAwait(false);
        return CreateException(operation, response.StatusCode, code, requestId);
    }

    public static HttpRequestException CreateStatusOnly(string operation, HttpResponseMessage response) =>
        CreateException(operation, response.StatusCode, code: null, TryGetRequestId(response));

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
        try
        {
            var body = await ReadBoundedBodyAsync(response, http, ct, deadlineCt, MaxSuccessBodyBytes).ConfigureAwait(false);
            return JsonSerializer.Deserialize<T>(body, options);
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

    private static HttpRequestException CreateException(
        string operation,
        HttpStatusCode statusCode,
        string? code,
        string? requestId)
    {
        var details = new List<string>(capacity: 2);
        if (!string.IsNullOrEmpty(code))
            details.Add($"code={code}");
        if (!string.IsNullOrEmpty(requestId))
            details.Add($"request_id={requestId}");

        var suffix = details.Count == 0
            ? string.Empty
            : $" [{string.Join(", ", details)}]";

        return new HttpRequestException(
            $"{operation} failed ({(int)statusCode}).{suffix}",
            inner: null,
            statusCode: statusCode);
    }

    private static async Task<string?> TryReadTransportCodeAsync(
        HttpResponseMessage response,
        HttpClient http,
        CancellationToken ct,
        CancellationToken? deadlineCt)
    {
        try
        {
            var body = await ReadBoundedBodyAsync(response, http, ct, deadlineCt, MaxErrorBodyBytes).ConfigureAwait(false);
            return ParseTransportCode(body, (int)response.StatusCode);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Response-body reads are diagnostic-only.  Any internal deadline,
            // read, or size failure falls back to status and safe headers.
            return null;
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

    private static string? ParseTransportCode(ReadOnlyMemory<byte> body, int statusCode)
    {
        if (body.IsEmpty)
            return null;

        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 16,
            });

            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return null;

            string? code = null;
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!string.Equals(property.Name, "error_code", StringComparison.Ordinal))
                    continue;
                if (code is not null || property.Value.ValueKind != JsonValueKind.String)
                    return null;
                code = property.Value.GetString();
            }

            if (string.IsNullOrEmpty(code) || !KnownTransportCodes.Contains(code))
                return null;

            if (string.Equals(code, "CSRF_FAILED", StringComparison.Ordinal))
                return statusCode == 403 ? code : null;

            var expectedCode = ErrorCodeByStatus.TryGetValue(statusCode, out var mappedCode)
                ? mappedCode
                : "REQUEST_FAILED";
            return string.Equals(code, expectedCode, StringComparison.Ordinal)
                ? code
                : null;
        }
        catch
        {
            return null;
        }
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
