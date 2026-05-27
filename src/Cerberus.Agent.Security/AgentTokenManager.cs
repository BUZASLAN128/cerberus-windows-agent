using System.Net.Http.Json;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Security;

public sealed class AgentTokenManager : ITokenManager
{
    private readonly HttpClient _http;
    private readonly ISecretStore _secrets;
    private readonly SemaphoreSlim _lock = new(1, 1);

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
            return await RefreshAndReturnAccessTokenAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task RefreshAsync(CancellationToken ct) =>
        _ = await RefreshAndReturnAccessTokenAsync(ct).ConfigureAwait(false);

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

        return payload.AccessToken;
    }

    private sealed record TokenRefreshPayload(
        [property: System.Text.Json.Serialization.JsonPropertyName("access_token")] string AccessToken,
        [property: System.Text.Json.Serialization.JsonPropertyName("expires_in")] int ExpiresIn,
        [property: System.Text.Json.Serialization.JsonPropertyName("refresh_token")] string? RefreshToken);
}
