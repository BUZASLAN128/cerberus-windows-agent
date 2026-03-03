using System.Net.Http.Json;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Security;

public sealed class AgentTokenManager : ITokenManager
{
    private readonly HttpClient _http;
    private readonly ISecretStore _secrets;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private string? _accessToken;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    public AgentTokenManager(HttpClient http, ISecretStore secrets)
    {
        _http = http;
        _secrets = secrets;
    }

    public async Task<string> GetAccessTokenAsync(CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            if (_accessToken is not null && DateTimeOffset.UtcNow < _expiresAt.AddSeconds(-30))
                return _accessToken;

            await RefreshAsync(ct);
            return _accessToken ?? throw new InvalidOperationException("Access token missing after refresh.");
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task RefreshAsync(CancellationToken ct)
    {
        var (id, refreshToken, _, _, _, _) = await _secrets.LoadAsync(ct);

        var req = new { agent_id = id.AgentId, refresh_token = refreshToken };
        var resp = await _http.PostAsJsonAsync("/api/v1/agents/token", req, cancellationToken: ct);
        resp.EnsureSuccessStatusCode();

        var payload = await resp.Content.ReadFromJsonAsync<TokenRefreshPayload>(cancellationToken: ct)
                      ?? throw new InvalidOperationException("Token refresh payload missing.");

        _accessToken = payload.AccessToken;
        _expiresAt = DateTimeOffset.UtcNow.AddSeconds(payload.ExpiresIn);

        // Rotation support: backend may return a new refresh token.
        if (!string.IsNullOrWhiteSpace(payload.RefreshToken))
        {
            // Preserve existing private key as-is.
            var (_, _, privateKeyPem, backendUrl, tsLogin, tsAuthkey) = await _secrets.LoadAsync(ct);
            await _secrets.SaveAsync(id, payload.RefreshToken!, privateKeyPem, backendUrl, tsLogin, tsAuthkey, ct);
        }
    }

    private sealed record TokenRefreshPayload(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")] int ExpiresIn,
        [property: System.Text.Json.Serialization.JsonPropertyName("refresh_token")] string? RefreshToken);
}
