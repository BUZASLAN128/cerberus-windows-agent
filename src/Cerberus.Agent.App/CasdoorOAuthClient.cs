using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.App;

internal sealed class CasdoorOAuthClient
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly Uri _baseUri;
    private readonly string _clientId;
    private readonly string? _clientSecret;
    private readonly string _scope;

    public CasdoorOAuthClient(Uri baseUri, string clientId, string? clientSecret, string scope)
    {
        _baseUri = baseUri;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _scope = scope;
    }

    public async Task<TokenResponse> LoginWithPkceAsync(int redirectPort, CancellationToken ct)
    {
        if (redirectPort <= 0 || redirectPort > 65535)
            throw new ArgumentOutOfRangeException(nameof(redirectPort));

        var state = Base64Url(RandomNumberGenerator.GetBytes(16));
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        // Use a loopback server implemented via TcpListener (no URLACL requirement).
        var redirect = new Uri($"http://127.0.0.1:{redirectPort}/callback");
        using var loopback = new LoopbackRedirectServer(redirectPort);

        var authorize = new UriBuilder(new Uri(_baseUri, "/login/oauth/authorize"));
        authorize.Query = string.Join(
            "&",
            $"client_id={Uri.EscapeDataString(_clientId)}",
            "response_type=code",
            $"redirect_uri={Uri.EscapeDataString(redirect.ToString())}",
            $"scope={Uri.EscapeDataString(_scope)}",
            $"state={Uri.EscapeDataString(state)}",
            $"code_challenge={Uri.EscapeDataString(challenge)}",
            "code_challenge_method=S256");

        OpenBrowser(authorize.Uri);

        var callback = await loopback.WaitForCodeAsync(ct);
        if (!string.Equals(callback.State, state, StringComparison.Ordinal))
            throw new InvalidOperationException("OAuth state mismatch.");

        using var http = new HttpClient { BaseAddress = _baseUri, Timeout = TimeSpan.FromSeconds(30) };

        // Casdoor token endpoint (common default).
        var tokenEndpoint = new Uri(_baseUri, "/api/login/oauth/access_token");

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = _clientId,
            ["code"] = callback.Code,
            ["redirect_uri"] = redirect.ToString(),
            ["code_verifier"] = verifier,
        };
        if (!string.IsNullOrWhiteSpace(_clientSecret))
            form["client_secret"] = _clientSecret!;

        using var req = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(form),
        };
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var resp = await http.SendAsync(req, ct);
        var raw = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Token exchange failed ({(int)resp.StatusCode}). {raw}");

        var parsed = JsonSerializer.Deserialize<TokenResponse>(raw, JsonOpts);
        if (parsed is null || string.IsNullOrWhiteSpace(parsed.AccessToken))
            throw new InvalidOperationException("Token exchange response missing access_token.");

        return parsed;
    }

    private static void OpenBrowser(Uri uri)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = uri.ToString(),
            UseShellExecute = true,
        });
    }

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    internal sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("token_type")] string? TokenType,
        [property: JsonPropertyName("expires_in")] int? ExpiresIn,
        [property: JsonPropertyName("refresh_token")] string? RefreshToken);
}

