using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

/// <summary>Process exit codes of <c>--enroll-headless</c>.</summary>
public static class HeadlessEnrollmentExit
{
    public const int Enrolled = 0;
    /// <summary>Bad proof or argument, missing precondition.</summary>
    public const int BadInput = 2;
    /// <summary>Request or response rejected; retrying the same input cannot help.</summary>
    public const int Rejected = 3;
    /// <summary>The proof is spent or refused (401, or 403 with any or no code), including a 2xx whose result was not stored; a new proof is required.</summary>
    public const int NewProofRequired = 4;
    /// <summary>429, 5xx, transport failure or timeout after the last attempt, or the service not ready to adopt.</summary>
    public const int Unavailable = 5;
    /// <summary>Wrong backend URL.</summary>
    public const int WrongBackend = 6;
    /// <summary>Local state refuses a new enrollment.</summary>
    public const int Refused = 7;
}

/// <summary>Non-secret device values sent with the proof.</summary>
public sealed record HeadlessEnrollmentOptions(
    string BackendUrlForStorage,
    string DeviceFingerprint,
    string AgentVersion,
    string? BuildId,
    string? BuildChannel,
    string DisplayName);

/// <summary>Outcome of one run. Never carries the proof, a token or a private key.</summary>
public sealed record HeadlessEnrollmentResult(
    int ExitCode,
    string Code,
    AgentIdentity? Identity = null,
    string? Fingerprint = null,
    string? TenantName = null)
{
    public bool Succeeded => ExitCode == HeadlessEnrollmentExit.Enrolled;
}

/// <summary>Format rules for the enrollment proof (an opaque JWT the agent does not verify).</summary>
public static class HeadlessEnrollmentProof
{
    public const int MinLength = 20;
    public const int MaxLength = 4096;
    public const int MaxSourceBytes = 8192;

    private static readonly Regex Shape = new(
        "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    /// <summary>Strips one leading BOM and surrounding ASCII whitespace, then checks length and shape.</summary>
    public static bool TryNormalize(string? raw, out string proof)
    {
        proof = "";
        if (raw is null)
            return false;
        var text = raw.Length > 0 && raw[0] == '﻿' ? raw[1..] : raw;
        text = text.Trim(' ', '\t', '\r', '\n', '\v', '\f');
        if (text.Length is < MinLength or > MaxLength || !Shape.IsMatch(text))
            return false;
        proof = text;
        return true;
    }

    /// <summary>
    /// Reads the string <c>agent_id</c> of the unverified proof payload into <paramref name="agentId"/> (null when absent,
    /// not a string or the payload is not JSON). Returns false only when the payload contains a JSON string
    /// (claim value or property name) that cannot be decoded.
    /// </summary>
    public static bool TryReadAgentId(string proof, out string? agentId)
    {
        agentId = null;
        try
        {
            var parts = proof.Split('.');
            if (parts.Length != 3)
                return true;
            var payload = parts[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
            using var document = JsonDocument.Parse(Convert.FromBase64String(payload));
            try
            {
                if (document.RootElement.ValueKind == JsonValueKind.Object &&
                    document.RootElement.TryGetProperty("agent_id", out var id) &&
                    id.ValueKind == JsonValueKind.String)
                {
                    agentId = id.GetString();
                }
            }
            catch (InvalidOperationException)
            {
                agentId = null;
                return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is FormatException or JsonException or ArgumentException)
        {
            return true;
        }
    }
}

/// <summary>Decides from local state alone whether a new enrollment may start.</summary>
public static class HeadlessEnrollmentGate
{
    /// <summary>
    /// Null when enrolling is allowed. Allowed: no machine credentials, NeedsReenrollment, or
    /// Retired for any reason except <c>agent_revoked</c>. A revoked registration is never replaced.
    /// </summary>
    public static string? Refusal(AgentLifecycleSnapshot state, bool hasMachineCredentials)
    {
        if (string.Equals(state.ReasonCode, AgentLifecycleStatePolicy.AgentRevokedCode, StringComparison.Ordinal))
            return "agent_revoked";
        if (!state.QuiescenceComplete)
            return "cleanup_pending";
        if (state.State is AgentLifecycleState.NeedsReenrollment or AgentLifecycleState.Retired)
            return null;
        return hasMachineCredentials ? "already_enrolled" : null;
    }
}

/// <summary>
/// One <c>--enroll-headless</c> run: proof check, local state gate, a fresh in-memory key,
/// the unsigned enroll request with bounded retries, response validation and a single
/// credential save. Nothing is saved on any failure; the proof is never logged or stored.
/// </summary>
public sealed class HeadlessEnrollment
{
    public const string Route = "/api/v1/agents/bootstrap/enroll-headless";
    public const int MaxAttempts = 3;

    private const int MaxErrorBodyBytes = 4096;
    private const int MaxSuccessBodyBytes = 64 * 1024;
    private static readonly TimeSpan MaxRetryAfter = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan[] DefaultDelays = [TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15)];
    private static readonly Regex AgentIdPattern = new("^[A-Za-z0-9-]{1,64}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex CodePattern = new("^[a-z0-9_]{1,64}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly IKeyPairGenerator _keys;
    private readonly IAgentLogger _log;
    private readonly TimeProvider _time;

    public HeadlessEnrollment(HttpClient http, IKeyPairGenerator? keys = null, IAgentLogger? log = null, TimeProvider? time = null)
    {
        _http = http;
        _keys = keys ?? RsaKeyPairGenerator.Instance;
        _log = log ?? NullAgentLogger.Instance;
        _time = time ?? TimeProvider.System;
    }

    /// <param name="rawProof">Proof text as read from its source.</param>
    /// <param name="state">Current lifecycle snapshot.</param>
    /// <param name="hasMachineCredentials">Whether a machine credential file exists.</param>
    /// <param name="destination">Receives the credentials once, only after a valid 2xx response.</param>
    public async Task<HeadlessEnrollmentResult> RunAsync(
        string rawProof,
        HeadlessEnrollmentOptions options,
        AgentLifecycleSnapshot state,
        bool hasMachineCredentials,
        ISecretStore destination,
        CancellationToken ct)
    {
        if (!HeadlessEnrollmentProof.TryNormalize(rawProof, out var proof))
            return new(HeadlessEnrollmentExit.BadInput, "proof_invalid");
        if (string.IsNullOrWhiteSpace(options.BackendUrlForStorage) || string.IsNullOrWhiteSpace(options.DeviceFingerprint) ||
            string.IsNullOrWhiteSpace(options.AgentVersion))
            return new(HeadlessEnrollmentExit.BadInput, "arguments_invalid");
        if (HeadlessEnrollmentGate.Refusal(state, hasMachineCredentials) is { } refusal)
            return new(HeadlessEnrollmentExit.Refused, refusal);
        if (!HeadlessEnrollmentProof.TryReadAgentId(proof, out var expectedAgentId))
            return new(HeadlessEnrollmentExit.BadInput, "proof_invalid");

        // A new key per run. Retries inside this run reuse it; it is never persisted before success.
        var (privateKeyPem, publicKeyPem) = _keys.GenerateKeyPair(2048);
        // Validated before the request: the 2xx spends the proof, so an unusable key must fail first.
        var fingerprint = AgentKeyFingerprint.TryFromPrivateKeyPem(privateKeyPem);
        if (fingerprint is null)
            return new(HeadlessEnrollmentExit.BadInput, "key_invalid");
        var body = BuildBody(proof, publicKeyPem, options);

        var (outcome, success) = await SendWithRetriesAsync(body, ct).ConfigureAwait(false);
        if (success is null)
            return outcome;

        if (expectedAgentId is not null && !string.Equals(expectedAgentId, success.AgentId, StringComparison.Ordinal))
            return new(HeadlessEnrollmentExit.NewProofRequired, "agent_id_mismatch");

        var identity = new AgentIdentity(success.AgentId, success.TenantId);
        try
        {
            // The destination store publishes atomically, so a failed save leaves the previous state intact.
            await destination.SaveAsync(identity, success.RefreshToken, privateKeyPem,
                options.BackendUrlForStorage.Trim().TrimEnd('/'), null, null, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Cancellation lands here too: the 2xx already spent the proof.
            _log.Error($"Headless enrollment credentials could not be saved ({ex.GetType().Name}).");
            // The proof is spent server-side and the in-memory key is gone.
            return new(HeadlessEnrollmentExit.NewProofRequired, "credentials_not_saved");
        }

        _log.Info($"Headless enrollment succeeded agent_id={identity.AgentId} tenant_id={identity.TenantId}");
        return new(HeadlessEnrollmentExit.Enrolled, "enrolled", identity, fingerprint, success.TenantName);
    }

    public static string FormatFingerprintLine(string fingerprint) => "Agent key fingerprint=" + fingerprint;

    private async Task<(HeadlessEnrollmentResult Outcome, EnrollSuccess? Success)> SendWithRetriesAsync(byte[] body, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            TimeSpan? retryAfter = null;
            string transientCode;
            try
            {
                using var content = new ByteArrayContent(body);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
                using var request = new HttpRequestMessage(HttpMethod.Post, Route) { Content = content };
                using var deadline = AgentHttpFailure.CreateDeadline(_http, ct);
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token)
                    .ConfigureAwait(false);
                var status = (int)response.StatusCode;
                if (response.IsSuccessStatusCode)
                {
                    try
                    {
                        return await ParseSuccessAsync(response, deadline.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException ex)
                    {
                        // The 2xx already spent the proof, so a cancelled or timed-out body read must not retry or exit as cancelled.
                        _log.Error($"Headless enrollment response could not be read ({ex.GetType().Name}).");
                        return (new(HeadlessEnrollmentExit.NewProofRequired, "response_not_read"), null);
                    }
                }

                var code = await ReadDetailCodeAsync(response, deadline.Token).ConfigureAwait(false);
                if (status != 429 && status < 500)
                {
                    var rejected = Classify(status, code);
                    _log.Warn($"Headless enrollment rejected status={status} code={code ?? "none"} exit={rejected.ExitCode}");
                    return (rejected, null);
                }
                retryAfter = ReadRetryAfter(response);
                transientCode = $"http_{status}";
            }
            catch (HttpRequestException)
            {
                transientCode = "transport_error";
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                transientCode = "transport_timeout";
            }

            if (attempt >= MaxAttempts)
            {
                _log.Warn($"Headless enrollment unavailable after {attempt} attempts ({transientCode}).");
                return (new(HeadlessEnrollmentExit.Unavailable, transientCode), null);
            }
            var delay = retryAfter ?? DefaultDelays[Math.Min(attempt - 1, DefaultDelays.Length - 1)];
            _log.Warn($"Headless enrollment attempt {attempt} failed ({transientCode}); retrying.");
            await Task.Delay(delay, _time, ct).ConfigureAwait(false);
        }
    }

    internal static HeadlessEnrollmentResult Classify(int status, string? code)
    {
        var label = code is null ? $"http_{status}" : $"http_{status}_{code}";
        return (status, code) switch
        {
            (401, _) or (403, _) => new(HeadlessEnrollmentExit.NewProofRequired, label),
            (409, "agent_proof_consumed") => new(HeadlessEnrollmentExit.NewProofRequired, label),
            (400, "agent_exists") => new(HeadlessEnrollmentExit.NewProofRequired, label),
            (404, _) or (400, "route_unavailable") => new(HeadlessEnrollmentExit.WrongBackend, label),
            _ => new(HeadlessEnrollmentExit.Rejected, label),
        };
    }

    private static async Task<(HeadlessEnrollmentResult, EnrollSuccess?)> ParseSuccessAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var bytes = await ReadLimitedAsync(response, MaxSuccessBodyBytes, ct).ConfigureAwait(false);
        if (bytes is not null)
        {
            try
            {
                using var document = JsonDocument.Parse(bytes);
                var root = document.RootElement;
                if (root.ValueKind == JsonValueKind.Object &&
                    Text(root, "agent_id", 64) is { } agentId && AgentIdPattern.IsMatch(agentId) &&
                    Text(root, "tenant_id", 256) is { } tenantId &&
                    Text(root, "agent_refresh_token", 8192) is { } refresh)
                {
                    return (new(HeadlessEnrollmentExit.Enrolled, "response_ok"),
                        new EnrollSuccess(agentId, tenantId, refresh, Text(root, "tenant_name", 256)));
                }
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException)
            {
                // InvalidOperationException: a string that parses but cannot be decoded (lone surrogate, invalid UTF-8).
            }
        }
        return (new(HeadlessEnrollmentExit.NewProofRequired, "response_invalid"), null);
    }

    private static string? Text(JsonElement root, string name, int maxLength)
        => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
           value.GetString() is { Length: > 0 } text && text.Length <= maxLength && text.Trim() == text
            ? text
            : null;

    private static async Task<string?> ReadDetailCodeAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var bytes = await ReadLimitedAsync(response, MaxErrorBodyBytes, ct).ConfigureAwait(false);
        if (bytes is null)
            return null;
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return null;
            var holder = root.TryGetProperty("detail", out var detail) && detail.ValueKind == JsonValueKind.Object ? detail : root;
            return holder.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
                   code.GetString() is { } text && CodePattern.IsMatch(text)
                ? text
                : null;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    private static async Task<byte[]?> ReadLimitedAsync(HttpResponseMessage response, int limit, CancellationToken ct)
    {
        try
        {
            if (response.Content.Headers.ContentLength is long length && length > limit)
                return null;
            await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            var buffer = new byte[limit + 1];
            var read = 0;
            while (read < buffer.Length)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(read), ct).ConfigureAwait(false);
                if (n == 0)
                    break;
                read += n;
            }
            return read > limit ? null : buffer.AsSpan(0, read).ToArray();
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidOperationException)
        {
            return null;
        }
    }

    private TimeSpan? ReadRetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter;
        TimeSpan? value = header?.Delta ?? (header?.Date is { } date ? date - _time.GetUtcNow() : null);
        if (value is null)
            return null;
        return value.Value < TimeSpan.Zero ? TimeSpan.Zero : value.Value > MaxRetryAfter ? MaxRetryAfter : value;
    }

    private static byte[] BuildBody(string proof, string publicKeyPem, HeadlessEnrollmentOptions o)
    {
        var version = Cut(o.AgentVersion.Trim(), 50);
        var request = new EnrollRequest(
            proof,
            publicKeyPem,
            o.DeviceFingerprint.Trim(),
            version,
            Cut(string.IsNullOrWhiteSpace(o.BuildId) ? version : o.BuildId.Trim(), 100),
            Cut(string.IsNullOrWhiteSpace(o.BuildChannel) ? "dev" : o.BuildChannel.Trim(), 50),
            ["agent.enroll.v1", "agent.heartbeat.v1"],
            Cut(string.IsNullOrWhiteSpace(o.DisplayName) ? "unknown" : o.DisplayName.Trim(), 120));
        return JsonSerializer.SerializeToUtf8Bytes(request, JsonOpts);
    }

    private static string Cut(string value, int max)
    {
        if (value.Length <= max)
            return value;
        var end = max;
        if (char.IsHighSurrogate(value[end - 1]))
            end--;
        return value[..end];
    }

    private sealed record EnrollSuccess(string AgentId, string TenantId, string RefreshToken, string? TenantName);

    private sealed record EnrollRequest(
        [property: JsonPropertyName("enrollment_proof")] string EnrollmentProof,
        [property: JsonPropertyName("agent_public_key_pem")] string AgentPublicKeyPem,
        [property: JsonPropertyName("device_fingerprint")] string DeviceFingerprint,
        [property: JsonPropertyName("agent_version")] string AgentVersion,
        [property: JsonPropertyName("build_id")] string BuildId,
        [property: JsonPropertyName("build_channel")] string BuildChannel,
        [property: JsonPropertyName("supported_schema_versions")] IReadOnlyList<string> SupportedSchemaVersions,
        [property: JsonPropertyName("display_name")] string DisplayName);
}
