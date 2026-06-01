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
    private string? _accessToken;
    private DateTimeOffset _accessTokenExpiresAt;

    public AgentTokenManager(HttpClient http, ISecretStore secrets)
        : this(http, secrets, null, null)
    {
    }

    public AgentTokenManager(
        HttpClient http,
        ISecretStore secrets,
        TimeSpan? refreshSafetyMargin,
        Func<DateTimeOffset>? utcNow)
    {
        _http = http;
        _secrets = secrets;
        _refreshSafetyMargin = refreshSafetyMargin ?? TimeSpan.FromSeconds(ReadSafetyMarginSeconds());
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public async Task<string> GetAccessTokenAsync(CancellationToken ct)
    {
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
        var resp = await _http.PostAsJsonAsync("/api/v1/agents/token", req, cancellationToken: ct);
        resp.EnsureSuccessStatusCode();

        var payload = await resp.Content.ReadFromJsonAsync<TokenRefreshPayload>(cancellationToken: ct)
                      ?? throw new InvalidOperationException("Token refresh payload missing.");

        // Rotation support: backend may return a new refresh token.
        if (!string.IsNullOrWhiteSpace(payload.RefreshToken))
        {
            await _secrets.SaveAsync(id, payload.RefreshToken!, privateKeyPem, backendUrl, tsLogin, tsAuthkey, ct);
        }

        _accessToken = payload.AccessToken;
        _accessTokenExpiresAt = _utcNow().AddSeconds(Math.Max(1, payload.ExpiresIn));
        return payload.AccessToken;
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
