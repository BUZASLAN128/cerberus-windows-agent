using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

internal static class AgentHttpFailure
{
    // Keep error inspection below the size used by the backend's compact error
    // envelope.  The response body is never included in a failure message.
    private const int MaxErrorBodyBytes = 4096;
    private const int MaxRequestIdLength = 64;

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

    public static async Task<HttpRequestException> CreateAsync(
        string operation,
        HttpResponseMessage response,
        CancellationToken ct)
    {
        var requestId = TryGetRequestId(response);
        var code = await TryReadTransportCodeAsync(response, ct).ConfigureAwait(false);
        return CreateException(operation, response.StatusCode, code, requestId);
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
        CancellationToken ct)
    {
        try
        {
            var content = response.Content;
            if (content is null || content.Headers.ContentLength is > MaxErrorBodyBytes)
                return null;

            await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var buffer = new byte[MaxErrorBodyBytes + 1];
            var length = 0;

            while (length < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(length), ct).ConfigureAwait(false);
                if (read == 0)
                    break;
                length += read;
            }

            // A body larger than the inspection budget is not parsed.  Reading
            // one extra byte lets this remain fail-closed when Content-Length is
            // absent or inaccurate.
            if (length == buffer.Length)
                return null;

            return ParseTransportCode(buffer.AsMemory(0, length), (int)response.StatusCode);
        }
        catch
        {
            // Response-body reads and JSON parsing are diagnostic-only.  Any
            // failure falls back to the status and independently safe header.
            return null;
        }
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
