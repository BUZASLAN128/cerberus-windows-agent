using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

/// <summary>
/// Client for communicating with the CERBERUS agent API backend.
/// Handles authentication, request signing, and API operations.
/// </summary>
public sealed class AgentApiClient
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly ISecretStore _secrets;
    private readonly ITokenManager _tokens;
    private readonly IRequestSigner _signer;

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentApiClient"/> class.
    /// </summary>
    /// <param name="http">HTTP client for API requests.</param>
    /// <param name="secrets">Secret store for agent credentials.</param>
    /// <param name="tokens">Token manager for access token refresh.</param>
    /// <param name="signer">Request signer for cryptographic signatures.</param>
    public AgentApiClient(HttpClient http, ISecretStore secrets, ITokenManager tokens, IRequestSigner signer)
    {
        _http = http;
        _secrets = secrets;
        _tokens = tokens;
        _signer = signer;
    }

    /// <summary>
    /// Sends a heartbeat to the backend and retrieves pending commands.
    /// </summary>
    /// <param name="body">Heartbeat request body containing agent status.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Heartbeat response with pending commands and next poll interval.</returns>
    /// <exception cref="HttpRequestException">Thrown when the API request fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the response is invalid.</exception>
    public async Task<HeartbeatResponse> HeartbeatAsync(object body, CancellationToken ct)
    {
        return await RetryHelper.WithRetryAsync(async () =>
        {
            var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
            var path = $"/api/v1/agents/{id.AgentId}/heartbeat";

            using var resp = await SendSignedRequestAsync(HttpMethod.Post, path, body, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();

            var payload = await resp.Content.ReadFromJsonAsync<HeartbeatResponse>(JsonOpts, ct).ConfigureAwait(false);
            return payload ?? throw new InvalidOperationException("Heartbeat response missing.");
        }, ct: ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Submits the result of a command execution to the backend.
    /// </summary>
    /// <param name="commandId">Command identifier.</param>
    /// <param name="body">Command result body containing status, exit code, and output.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <exception cref="HttpRequestException">Thrown when the API request fails.</exception>
    public async Task SubmitCommandResultAsync(string commandId, object body, CancellationToken ct)
    {
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/commands/{commandId}/result";

        using var resp = await SendSignedRequestAsync(HttpMethod.Post, path, body, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
    }

    public Task<AgentIngestAckResponse> SubmitSnapshotAsync(AgentSnapshotRequest body, CancellationToken ct) =>
        SubmitIngestAsync("snapshot", body, retryTransient: true, ct: ct);

    public Task<AgentIngestAckResponse> SubmitEventsAsync(AgentEventBatchRequest body, CancellationToken ct) =>
        SubmitIngestAsync("events", body, retryTransient: false, ct: ct);

    public Task<AgentIngestAckResponse> SubmitProbeResultAsync(AgentProbeResultRequest body, CancellationToken ct) =>
        SubmitIngestAsync("probe-results", body, retryTransient: true, ct: ct);

    public async Task<AgentDiagnosticBundleAckResponse> SubmitDiagnosticBundleAsync(
        AgentDiagnosticBundleRequest body,
        CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/diagnostic-bundles";

        return await RetryHelper.WithRetryAsync(async () =>
        {
            using var resp = await SendSignedJsonRequestAsync(HttpMethod.Post, path, json, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();

            var payload = await resp.Content.ReadFromJsonAsync<AgentDiagnosticBundleAckResponse>(JsonOpts, ct).ConfigureAwait(false);
            return payload ?? throw new InvalidOperationException("Agent diagnostic bundle response missing.");
        }, maxRetries: 1, ct: ct).ConfigureAwait(false);
    }

    public async Task<AgentIngestAckResponse> SubmitOfflineTelemetryAsync(OfflineTelemetryRecord record, CancellationToken ct)
    {
        var endpoint = record.Kind switch
        {
            OfflineTelemetryKinds.Snapshot => "snapshot",
            OfflineTelemetryKinds.Events => "events",
            OfflineTelemetryKinds.ProbeResult => "probe-results",
            _ => throw new InvalidOperationException($"Unknown offline telemetry kind: {record.Kind}"),
        };
        var retryTransient = record.Kind switch
        {
            OfflineTelemetryKinds.Snapshot => true,
            OfflineTelemetryKinds.ProbeResult => true,
            _ => false,
        };
        return await SubmitIngestJsonAsync(endpoint, record.Json, retryTransient, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Requests a fresh Tailscale preauth key from the backend.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Tuple containing login server URL and auth key.</returns>
    /// <exception cref="HttpRequestException">Thrown when the API request fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the response is invalid.</exception>
    public async Task<(string LoginServer, string AuthKey)> GetTailscalePreauthAsync(CancellationToken ct)
    {
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/tailscale/preauth";

        using var resp = await SendSignedRequestAsync(HttpMethod.Post, path, new { }, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw AgentHttpFailure.Create("Tailscale preauth", resp);

        var payload = await resp.Content.ReadFromJsonAsync<TailscalePreauthResponse>(JsonOpts, ct).ConfigureAwait(false);
        if (payload is null ||
            string.IsNullOrWhiteSpace(payload.TailscaleLoginServer) ||
            string.IsNullOrWhiteSpace(payload.TailscaleAuthkey))
            throw new InvalidOperationException("Tailscale preauth response missing.");

        return (payload.TailscaleLoginServer, payload.TailscaleAuthkey);
    }

    public async Task<AgentSelfDeactivateResponse> SelfDeactivateAsync(AgentSelfDeactivateRequest body, CancellationToken ct)
    {
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/deactivate";

        using var resp = await SendSignedRequestAsync(HttpMethod.Post, path, body, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        var payload = await resp.Content.ReadFromJsonAsync<AgentSelfDeactivateResponse>(JsonOpts, ct).ConfigureAwait(false);
        return payload ?? throw new InvalidOperationException("Agent self-deactivate response missing.");
    }

    private async Task<AgentIngestAckResponse> SubmitIngestAsync(
        string endpoint,
        object body,
        bool retryTransient,
        CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        return await SubmitIngestJsonAsync(endpoint, json, retryTransient, ct).ConfigureAwait(false);
    }

    private async Task<AgentIngestAckResponse> SubmitIngestJsonAsync(
        string endpoint,
        string json,
        bool retryTransient,
        CancellationToken ct)
    {
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/{endpoint}";

        async Task<AgentIngestAckResponse> SubmitOnceAsync()
        {
            using var resp = await SendSignedJsonRequestAsync(HttpMethod.Post, path, json, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();

            var payload = await resp.Content.ReadFromJsonAsync<AgentIngestAckResponse>(JsonOpts, ct).ConfigureAwait(false);
            return payload ?? throw new InvalidOperationException("Agent ingestion response missing.");
        }

        return retryTransient
            ? await RetryHelper.WithRetryAsync(SubmitOnceAsync, maxRetries: 1, ct: ct).ConfigureAwait(false)
            : await SubmitOnceAsync().ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendSignedRequestAsync(
        HttpMethod method,
        string path,
        object body,
        CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        return await SendSignedJsonRequestAsync(method, path, json, ct).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendSignedJsonRequestAsync(
        HttpMethod method,
        string path,
        string json,
        CancellationToken ct)
    {
        var response = await SendSignedJsonRequestOnceAsync(method, path, json, ct).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        response.Dispose();
        await _tokens.RefreshAsync(ct).ConfigureAwait(false);
        return await SendSignedJsonRequestOnceAsync(method, path, json, ct).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendSignedJsonRequestOnceAsync(
        HttpMethod method,
        string path,
        string json,
        CancellationToken ct)
    {
        using var req = await BuildSignedJsonRequestAsync(method, path, json, ct).ConfigureAwait(false);
        return await _http.SendAsync(req, ct).ConfigureAwait(false);
    }

    private async Task<HttpRequestMessage> BuildSignedJsonRequestAsync(HttpMethod method, string path, string json, CancellationToken ct)
    {
        var accessToken = await _tokens.GetAccessTokenAsync(ct).ConfigureAwait(false);

        var bodyBytes = Encoding.UTF8.GetBytes(json);
        var bodyHash = _signer.ComputeBodyHash(bodyBytes);

        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var canonical = _signer.CanonicalString(method.Method, path, nonce, ts, bodyHash);
        var sig = _signer.Sign(canonical);

        var req = new HttpRequestMessage(method, path)
        {
            Content = new ByteArrayContent(bodyBytes),
        };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        req.Headers.Add("X-Agent-Id", id.AgentId);
        req.Headers.Add("X-Nonce", nonce);
        req.Headers.Add("X-Timestamp", ts.ToString());
        req.Headers.Add("X-Body-Hash", bodyHash);
        req.Headers.Add("X-Signature", sig);

        return req;
    }

    private sealed record TailscalePreauthResponse(
        [property: JsonPropertyName("tailscale_login_server")] string TailscaleLoginServer,
        [property: JsonPropertyName("tailscale_authkey")] string TailscaleAuthkey);
}
