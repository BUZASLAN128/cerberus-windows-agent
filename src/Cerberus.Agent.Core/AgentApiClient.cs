using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.CompilerServices;

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
    private readonly IAgentLifecycleStateStore? _lifecycleState;
    private readonly bool _manualOperation;
    private readonly Func<CancellationToken, Task>? _quiesce;
    private static readonly HttpRequestOptionsKey<long> LifecycleGenerationKey = new("CerberusLifecycleGeneration");
    private static readonly ConditionalWeakTable<HeartbeatResponse, ResponseGeneration> ResponseGenerations = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentApiClient"/> class.
    /// </summary>
    /// <param name="http">HTTP client for API requests.</param>
    /// <param name="secrets">Secret store for agent credentials.</param>
    /// <param name="tokens">Token manager for access token refresh.</param>
    /// <param name="signer">Request signer for cryptographic signatures.</param>
    public AgentApiClient(
        HttpClient http,
        ISecretStore secrets,
        ITokenManager tokens,
        IRequestSigner signer,
        IAgentLifecycleStateStore? lifecycleState = null,
        bool manualOperation = false,
        Func<CancellationToken, Task>? quiesce = null)
    {
        _http = http;
        _secrets = secrets;
        _tokens = tokens;
        _signer = signer;
        _lifecycleState = lifecycleState;
        _manualOperation = manualOperation;
        _quiesce = quiesce;
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
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/heartbeat";

        using var deadline = AgentHttpFailure.CreateDeadline(_http, ct);
        using var resp = await SendSignedRequestAsync(
            HttpMethod.Post,
            path,
            body,
            ct,
            HttpCompletionOption.ResponseHeadersRead,
            deadline.Token).ConfigureAwait(false);
        await EnsureSuccessAsync("Heartbeat", resp, ct, deadline.Token).ConfigureAwait(false);

        HeartbeatResponse? payload;
        try
        {
            payload = await AgentHttpFailure.ReadJsonAsync<HeartbeatResponse>(
                "Heartbeat",
                resp,
                _http,
                JsonOpts,
                ct,
                deadline.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException ex) when (_lifecycleState is not null && AgentHttpFailure.IsPayloadInvalid(ex))
        {
            await _lifecycleState.TransitionAsync(
                AgentLifecycleState.BlockedConfig,
                reasonCode: "heartbeat_response_invalid",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct, expectedGeneration: RequestGeneration(resp)).ConfigureAwait(false);
            throw;
        }
        if (payload is null ||
            payload.PendingCommands is null ||
            payload.NextPollSeconds <= 0 ||
            payload.NextSnapshotSeconds < 0)
        {
            if (_lifecycleState is not null)
            {
                await _lifecycleState.TransitionAsync(
                    AgentLifecycleState.BlockedConfig,
                    reasonCode: "heartbeat_response_invalid",
                    requestId: null,
                    nextAttemptUtc: null,
                    genericAuthFailureCount: null,
                    ct, expectedGeneration: RequestGeneration(resp)).ConfigureAwait(false);
            }
            throw new InvalidOperationException("Heartbeat response missing or invalid.");
        }

        if (_lifecycleState is not null)
        {
            var lifecycle = await new AgentLifecycleController(_lifecycleState)
                .MarkActiveAsync(ct, RequestGeneration(resp)).ConfigureAwait(false);
            ResponseGenerations.Add(payload, new ResponseGeneration(lifecycle.Generation));
        }
        return payload;
    }

    public async Task<ManagedAccountManifest> GetManagedAccountManifestAsync(CancellationToken ct)
    {
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var (identity, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        using var deadline = AgentHttpFailure.CreateDeadline(_http, ct);
        using var response = await SendSignedJsonRequestAsync(HttpMethod.Get,
            $"/api/v1/agents/{identity.AgentId}/managed-accounts/manifest", "", ct,
            HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        await EnsureSuccessAsync("Managed account manifest", response, ct, deadline.Token).ConfigureAwait(false);
        var manifest = await AgentHttpFailure.ReadJsonAsync<ManagedAccountManifest>("Managed account manifest",
            response, _http, JsonOpts, ct, deadline.Token).ConfigureAwait(false);
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        if (_lifecycleState is not null &&
            (await _lifecycleState.LoadAsync(ct).ConfigureAwait(false)).Generation != RequestGeneration(response))
            throw new InvalidOperationException("Manifest enrollment generation changed.");
        return manifest ?? throw new InvalidOperationException("Managed account manifest missing.");
    }

    public async Task<AdCommandAuthority> GetAdCommandAuthorityAsync(AgentCommand command, CancellationToken ct)
    {
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(command.Id) || command.Id.Length > 128 ||
            string.IsNullOrWhiteSpace(command.LeaseId) || command.LeaseId.Length > 128)
            throw new InvalidOperationException("AD command lease is required.");
        var (identity, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        using var deadline = AgentHttpFailure.CreateDeadline(_http, ct);
        using var response = await SendSignedRequestAsync(HttpMethod.Post,
            $"/api/v1/agents/{Uri.EscapeDataString(identity.AgentId)}/commands/{Uri.EscapeDataString(command.Id)}/ad-authority",
            new { lease_id = command.LeaseId }, ct, HttpCompletionOption.ResponseHeadersRead, deadline.Token,
            resourceOperation: true).ConfigureAwait(false);
        await EnsureSuccessAsync("AD command authority", response, ct, deadline.Token,
            resourceOperation: true).ConfigureAwait(false);
        var authority = await AgentHttpFailure.ReadJsonAsync<AdCommandAuthority>("AD command authority",
            response, _http, JsonOpts, ct, deadline.Token).ConfigureAwait(false);
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        if (_lifecycleState is not null &&
            (await _lifecycleState.LoadAsync(ct).ConfigureAwait(false)).Generation != RequestGeneration(response))
            throw new InvalidOperationException("AD authority enrollment generation changed.");
        if (authority is null || authority.TenantId != identity.TenantId || authority.AgentId != identity.AgentId ||
            authority.Command is null || authority.ExpiresAt.Offset != TimeSpan.Zero ||
            authority.ExpiresAt <= DateTimeOffset.UtcNow || authority.ExpiresAt > DateTimeOffset.UtcNow.AddSeconds(30))
            throw new InvalidOperationException("AD command authority is invalid.");
        return authority;
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
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/commands/{commandId}/result";

        using var resp = await SendSignedRequestAsync(
            HttpMethod.Post,
            path,
            body,
            ct,
            HttpCompletionOption.ResponseHeadersRead,
            resourceOperation: true).ConfigureAwait(false);
        await EnsureSuccessAsync("Command result", resp, ct, resourceOperation: true).ConfigureAwait(false);
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
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var json = JsonSerializer.Serialize(body, JsonOpts);
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/diagnostic-bundles";

        async Task<AgentDiagnosticBundleAckResponse> SubmitOnceAsync()
        {
            using var resp = await SendSignedJsonRequestAsync(
                HttpMethod.Post,
                path,
                json,
                ct,
                HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            await EnsureSuccessAsync("Agent diagnostic bundle", resp, ct).ConfigureAwait(false);

            var payload = await AgentHttpFailure.ReadJsonAsync<AgentDiagnosticBundleAckResponse>(
                "Agent diagnostic bundle",
                resp,
                _http,
                JsonOpts,
                ct).ConfigureAwait(false);
            return payload ?? throw new InvalidOperationException("Agent diagnostic bundle response missing.");
        }

        return await RetryHelper.WithRetryAsync(SubmitOnceAsync, maxRetries: 1, ct: ct).ConfigureAwait(false);
    }

    public async Task<AgentIngestAckResponse> SubmitOfflineTelemetryAsync(OfflineTelemetryRecord record, CancellationToken ct)
    {
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
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
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/tailscale/preauth";

        using var deadline = AgentHttpFailure.CreateDeadline(_http, ct);
        using var resp = await SendSignedRequestAsync(
            HttpMethod.Post,
            path,
            new { },
            ct,
            HttpCompletionOption.ResponseHeadersRead,
            deadline.Token).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw await AgentHttpFailure.CreateAsync(
                "Tailscale preauth",
                resp,
                _http,
                ct,
                deadline.Token).ConfigureAwait(false);

        var payload = await AgentHttpFailure.ReadJsonAsync<TailscalePreauthResponse>(
            "Tailscale preauth",
            resp,
            _http,
            JsonOpts,
            ct,
            deadline.Token).ConfigureAwait(false);
        if (payload is null ||
            string.IsNullOrWhiteSpace(payload.TailscaleLoginServer) ||
            string.IsNullOrWhiteSpace(payload.TailscaleAuthkey))
            throw new InvalidOperationException("Tailscale preauth response missing.");

        return (payload.TailscaleLoginServer, payload.TailscaleAuthkey);
    }

    public async Task<AgentSelfDeactivateResponse> SelfDeactivateAsync(AgentSelfDeactivateRequest body, CancellationToken ct)
    {
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/deactivate";

        using var resp = await SendSignedRequestAsync(
            HttpMethod.Post,
            path,
            body,
            ct,
            HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        await EnsureSuccessAsync("Agent self-deactivate", resp, ct).ConfigureAwait(false);

        var payload = await AgentHttpFailure.ReadJsonAsync<AgentSelfDeactivateResponse>(
            "Agent self-deactivate",
            resp,
            _http,
            JsonOpts,
            ct).ConfigureAwait(false);
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
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/{endpoint}";

        async Task<AgentIngestAckResponse> SubmitOnceAsync()
        {
            using var resp = await SendSignedJsonRequestAsync(
                HttpMethod.Post,
                path,
                json,
                ct,
                HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            await EnsureSuccessAsync($"Agent {endpoint}", resp, ct).ConfigureAwait(false);

            var payload = await AgentHttpFailure.ReadJsonAsync<AgentIngestAckResponse>(
                $"Agent {endpoint}",
                resp,
                _http,
                JsonOpts,
                ct).ConfigureAwait(false);
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
        CancellationToken ct,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead,
        CancellationToken? deadlineCt = null,
        bool resourceOperation = false)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        return await SendSignedJsonRequestAsync(method, path, json, ct, completionOption, deadlineCt,
            resourceOperation).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendSignedJsonRequestAsync(
        HttpMethod method,
        string path,
        string json,
        CancellationToken ct,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead,
        CancellationToken? deadlineCt = null,
        bool resourceOperation = false)
    {
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var response = await SendSignedJsonRequestOnceAsync(
            method,
            path,
            json,
            ct,
            completionOption,
            deadlineCt).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        if (_lifecycleState is not null)
        {
            var accessFailure = await AgentHttpFailure.CreateAsync(
                "Agent request",
                response,
                _http,
                ct,
                deadlineCt).ConfigureAwait(false);
            if (accessFailure is AgentHttpException typed &&
                (AgentLifecycleStatePolicy.IsTerminalCode(typed.Code) || typed.Code == AgentLifecycleStatePolicy.AgentReenrollRequiredCode))
            {
                response.Dispose();
                await new AgentLifecycleController(_lifecycleState, _secrets, quiesce: _quiesce)
                    .RecordHttpFailureAsync(
                        typed.Failure,
                        duringRefresh: false,
                        manualOperation: _manualOperation,
                        ct,
                        expectedGeneration: RequestGeneration(response),
                        authenticatedControlPlane: true)
                    .ConfigureAwait(false);
                throw accessFailure;
            }
        }

        response.Dispose();
        await _tokens.RefreshAsync(ct).ConfigureAwait(false);
        var retried = await SendSignedJsonRequestOnceAsync(
            method,
            path,
            json,
            ct,
            completionOption,
            deadlineCt).ConfigureAwait(false);

        if (_lifecycleState is not null &&
            (retried.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden ||
             (!resourceOperation && retried.StatusCode is (HttpStatusCode.NotFound or HttpStatusCode.Conflict))))
        {
            var retryFailure = await AgentHttpFailure.CreateAsync(
                "Agent request",
                retried,
                _http,
                ct,
                deadlineCt).ConfigureAwait(false);
            retried.Dispose();
            var retryInfo = retryFailure is AgentHttpException typed
                ? typed.Failure
                : new AgentHttpFailureInfo(
                    retryFailure.StatusCode ?? retried.StatusCode,
                    TransportCode: null,
                    DetailCode: null,
                    Status: null,
                    RequestId: null,
                    RetryAfter: null);
            await new AgentLifecycleController(_lifecycleState, _secrets, quiesce: _quiesce)
                .RecordHttpFailureAsync(
                    retryInfo,
                    duringRefresh: false,
                    manualOperation: _manualOperation,
                    ct,
                    expectedGeneration: RequestGeneration(retried),
                    authenticatedControlPlane: true,
                    resourceOperation: resourceOperation)
                .ConfigureAwait(false);
            throw retryFailure;
        }

        return retried;
    }

    private async Task EnsureSuccessAsync(
        string operation,
        HttpResponseMessage response,
        CancellationToken ct,
        CancellationToken? deadlineCt = null,
        bool resourceOperation = false)
    {
        if (response.IsSuccessStatusCode)
            return;

        var failure = await AgentHttpFailure.CreateAsync(
            operation,
            response,
            _http,
            ct,
            deadlineCt).ConfigureAwait(false);
        if (_lifecycleState is not null)
        {
            var failureInfo = failure is AgentHttpException typed
                ? typed.Failure
                : new AgentHttpFailureInfo(
                    failure.StatusCode ?? response.StatusCode,
                    TransportCode: null,
                    DetailCode: null,
                    Status: null,
                    RequestId: null,
                    RetryAfter: null);
            await new AgentLifecycleController(_lifecycleState, _secrets, quiesce: _quiesce)
                .RecordHttpFailureAsync(
                    failureInfo,
                    duringRefresh: false,
                    manualOperation: _manualOperation,
                    ct,
                    expectedGeneration: RequestGeneration(response),
                    authenticatedControlPlane: true,
                    resourceOperation: resourceOperation)
                .ConfigureAwait(false);
        }
        throw failure;
    }

    private async Task EnsureAutomaticNetworkAllowedAsync(CancellationToken ct)
    {
        if (_lifecycleState is null)
            return;

        if (_manualOperation)
        {
            var manualSnapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
            if (manualSnapshot.State is AgentLifecycleState.Retired or AgentLifecycleState.NeedsReenrollment || !manualSnapshot.QuiescenceComplete)
                throw new AgentLifecycleDormantException(manualSnapshot);
            return;
        }

        await new AgentLifecycleController(_lifecycleState, _secrets)
            .EnsureAutomaticNetworkAllowedAsync(ct)
            .ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendSignedJsonRequestOnceAsync(
        HttpMethod method,
        string path,
        string json,
        CancellationToken ct,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead,
        CancellationToken? deadlineCt = null)
    {
        using var req = await BuildSignedJsonRequestAsync(method, path, json, ct).ConfigureAwait(false);
        return await _http.SendAsync(req, completionOption, deadlineCt ?? ct).ConfigureAwait(false);
    }

    private async Task<HttpRequestMessage> BuildSignedJsonRequestAsync(HttpMethod method, string path, string json, CancellationToken ct)
    {
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var generation = _lifecycleState is null ? (long?)null : (await _lifecycleState.LoadAsync(ct).ConfigureAwait(false)).Generation;
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
        if (generation is not null)
        {
            var current = await _lifecycleState!.LoadAsync(ct).ConfigureAwait(false);
            if (current.Generation != generation)
            {
                req.Dispose();
                throw new AgentLifecycleDormantException(current);
            }
            req.Options.Set(LifecycleGenerationKey, generation.Value);
        }
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

    private static long? RequestGeneration(HttpResponseMessage response)
        => response.RequestMessage?.Options.TryGetValue(LifecycleGenerationKey, out var value) == true ? value : null;

    internal static long? GenerationOf(HeartbeatResponse response)
        => ResponseGenerations.TryGetValue(response, out var value) ? value.Value : null;

    private sealed record ResponseGeneration(long Value);

    private sealed record TailscalePreauthResponse(
        [property: JsonPropertyName("tailscale_login_server")] string TailscaleLoginServer,
        [property: JsonPropertyName("tailscale_authkey")] string TailscaleAuthkey);
}
