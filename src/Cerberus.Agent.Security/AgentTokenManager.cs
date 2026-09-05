using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Security;

public sealed class AgentTokenManager : ITokenManager
{
    private readonly HttpClient _http;
    private readonly ISecretStore _secrets;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly TimeSpan _refreshSafetyMargin;
    private readonly Func<DateTimeOffset> _utcNow;
    private readonly IAgentLifecycleStateStore? _lifecycleState;
    private readonly bool _manualOperation;
    private string? _accessToken;
    private DateTimeOffset _accessTokenExpiresAt;

    public AgentTokenManager(HttpClient http, ISecretStore secrets)
        : this(http, secrets, null, null, null, false)
    {
    }

    public AgentTokenManager(
        HttpClient http,
        ISecretStore secrets,
        TimeSpan? refreshSafetyMargin = null,
        Func<DateTimeOffset>? utcNow = null,
        IAgentLifecycleStateStore? lifecycleState = null,
        bool manualOperation = false)
    {
        _http = http;
        _secrets = secrets;
        _refreshSafetyMargin = refreshSafetyMargin ?? TimeSpan.FromSeconds(ReadSafetyMarginSeconds());
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
        _lifecycleState = lifecycleState;
        _manualOperation = manualOperation;
    }

    public async Task<string> GetAccessTokenAsync(CancellationToken ct)
    {
        await EnsureNetworkAllowedAsync(ct).ConfigureAwait(false);
        await _lock.WaitAsync(ct);
        try
        {
            if (!string.IsNullOrWhiteSpace(_accessToken) && _accessTokenExpiresAt - _utcNow() > _refreshSafetyMargin)
            {
                return _accessToken;
            }
            return await RefreshAndReturnAccessTokenAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task RefreshAsync(CancellationToken ct)
    {
        await EnsureNetworkAllowedAsync(ct).ConfigureAwait(false);
        await _lock.WaitAsync(ct);
        try
        {
            _ = await RefreshAndReturnAccessTokenAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<string> RefreshAndReturnAccessTokenAsync(CancellationToken ct)
    {
        var (id, refreshToken, privateKeyPem, backendUrl, tsLogin, tsAuthkey) = await _secrets.LoadAsync(ct);

        var req = new { agent_id = id.AgentId, refresh_token = refreshToken };
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/token")
        {
            Content = JsonContent.Create(req),
        };
        using var deadline = AgentHttpFailure.CreateDeadline(_http, ct);
        using var resp = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            deadline.Token).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            var failure = await AgentHttpFailure.CreateAsync(
                "Token refresh",
                resp,
                _http,
                ct,
                deadline.Token).ConfigureAwait(false);
            if (_lifecycleState is not null)
            {
                var failureInfo = failure is AgentHttpException typed
                    ? typed.Failure
                    : new AgentHttpFailureInfo(
                        failure.StatusCode ?? resp.StatusCode,
                        TransportCode: null,
                        DetailCode: null,
                        Status: null,
                        RequestId: null,
                        RetryAfter: null);
                await new AgentLifecycleController(_lifecycleState, _secrets)
                    .RecordHttpFailureAsync(
                        failureInfo,
                        duringRefresh: true,
                        manualOperation: _manualOperation,
                        ct)
                    .ConfigureAwait(false);
            }
            throw failure;
        }

        TokenRefreshPayload? payload;
        try
        {
            payload = await AgentHttpFailure.ReadJsonAsync<TokenRefreshPayload>(
                "Token refresh",
                resp,
                _http,
                new JsonSerializerOptions(JsonSerializerDefaults.Web),
                ct,
                deadline.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException ex) when (_lifecycleState is not null && AgentHttpFailure.IsPayloadInvalid(ex))
        {
            await TransitionInvalidPayloadAsync(ct).ConfigureAwait(false);
            throw;
        }

        if (payload is null)
            throw await HandleInvalidPayloadAsync(ct).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(payload.AccessToken) || payload.ExpiresIn <= 0)
            throw await HandleInvalidPayloadAsync(ct).ConfigureAwait(false);

        // Rotation support: backend may return a new refresh token.
        if (!string.IsNullOrWhiteSpace(payload.RefreshToken))
        {
            await _secrets.SaveAsync(id, payload.RefreshToken!, privateKeyPem, backendUrl, tsLogin, tsAuthkey, ct);
        }

        _accessToken = payload.AccessToken;
        _accessTokenExpiresAt = _utcNow().AddSeconds(Math.Max(1, payload.ExpiresIn));
        return payload.AccessToken;
    }

    private async Task<Exception> HandleInvalidPayloadAsync(CancellationToken ct)
    {
        await TransitionInvalidPayloadAsync(ct).ConfigureAwait(false);
        return new InvalidOperationException("Token refresh payload missing or invalid.");
    }

    private Task TransitionInvalidPayloadAsync(CancellationToken ct)
        => _lifecycleState is null
            ? Task.CompletedTask
            : _lifecycleState.TransitionAsync(
                AgentLifecycleState.BlockedConfig,
                reasonCode: "token_response_invalid",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct);

    private async Task EnsureNetworkAllowedAsync(CancellationToken ct)
    {
        if (_lifecycleState is null)
            return;

        if (_manualOperation)
        {
            var manualSnapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
            if (manualSnapshot.State == AgentLifecycleState.Retired)
                throw new AgentRetiredException(manualSnapshot);
            return;
        }

        await new AgentLifecycleController(_lifecycleState, _secrets)
            .EnsureAutomaticNetworkAllowedAsync(ct)
            .ConfigureAwait(false);
    }

    private static int ReadSafetyMarginSeconds()
    {
        var value = Environment.GetEnvironmentVariable("CERBERUS_AGENT_TOKEN_REFRESH_SAFETY_MARGIN_SECONDS");
        if (string.IsNullOrWhiteSpace(value))
        {
            value = Environment.GetEnvironmentVariable("AGENT_TOKEN_REFRESH_SAFETY_MARGIN_SECONDS");
        }
        return int.TryParse(value, out var parsed) && parsed >= 0 ? parsed : 90;
    }

    private sealed record TokenRefreshPayload(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")] int ExpiresIn,
        [property: System.Text.Json.Serialization.JsonPropertyName("refresh_token")] string? RefreshToken);
}
