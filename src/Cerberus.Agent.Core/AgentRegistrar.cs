using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

/// <summary>
/// Handles agent registration with the CERBERUS backend.
/// For first-time enrollment, generates RSA key pairs, exchanges OAuth tokens, and persists agent credentials.
/// </summary>
public sealed class AgentRegistrar
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly ISecretStore _secrets;
    private readonly IKeyPairGenerator _keyPairs;
    private readonly IAgentLogger _log;

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentRegistrar"/> class.
    /// </summary>
    /// <param name="http">HTTP client for API requests.</param>
    /// <param name="secrets">Secret store for persisting agent credentials.</param>
    /// <param name="keyPairs">Key pair generator for RSA keys (optional, defaults to RSA 2048-bit).</param>
    /// <param name="log">Logger for registration events (optional).</param>
    public AgentRegistrar(
        HttpClient http,
        ISecretStore secrets,
        IKeyPairGenerator? keyPairs = null,
        IAgentLogger? log = null)
    {
        _http = http;
        _secrets = secrets;
        _keyPairs = keyPairs ?? RsaKeyPairGenerator.Instance;
        _log = log ?? NullAgentLogger.Instance;
    }

    /// <summary>
    /// Registers the agent with the backend using an OAuth token.
    /// </summary>
    /// <param name="oauthToken">OAuth access token from SSO provider.</param>
    /// <param name="backendUrlForStorage">Backend URL to persist for future API calls.</param>
    /// <param name="deviceFingerprint">Unique device fingerprint for identification.</param>
    /// <param name="agentVersion">Agent version string.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Agent identity containing agent ID and tenant ID.</returns>
    /// <exception cref="ArgumentException">Thrown when required parameters are missing.</exception>
    /// <exception cref="HttpRequestException">Thrown when registration fails.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the response is invalid.</exception>
    public async Task<AgentIdentity> RegisterAsync(
        string oauthToken,
        string backendUrlForStorage,
        string deviceFingerprint,
        string agentVersion,
        string? buildId,
        string? buildChannel,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(oauthToken))
            throw new ArgumentException("oauthToken is required.", nameof(oauthToken));
        if (string.IsNullOrWhiteSpace(backendUrlForStorage))
            throw new ArgumentException("backendUrlForStorage is required.", nameof(backendUrlForStorage));
        if (string.IsNullOrWhiteSpace(deviceFingerprint))
            throw new ArgumentException("deviceFingerprint is required.", nameof(deviceFingerprint));
        if (string.IsNullOrWhiteSpace(agentVersion))
            throw new ArgumentException("agentVersion is required.", nameof(agentVersion));

        var existingIdentity = await TryLoadExistingRegistrationAsync(ct).ConfigureAwait(false);
        if (existingIdentity is not null)
        {
            _log.Info("Existing agent registration found; register skipped.");
            return existingIdentity;
        }

        var (privPem, pubPem) = _keyPairs.GenerateKeyPair(2048);

        var req = new AgentRegisterRequest(
            OauthToken: oauthToken.Trim(),
            AgentPublicKeyPem: pubPem,
            DeviceFingerprint: deviceFingerprint,
            AgentVersion: agentVersion,
            BuildId: string.IsNullOrWhiteSpace(buildId) ? agentVersion : buildId.Trim(),
            BuildChannel: string.IsNullOrWhiteSpace(buildChannel) ? "dev" : buildChannel.Trim(),
            SupportedSchemaVersions: new[] { "agent.enroll.v1", "agent.heartbeat.v1" },
            DisplayName: Environment.MachineName,
            PurposeNote: "Self-enrolled Windows agent",
            LocationHint: null);

        _log.Info("Registering agent...");
        using var registerRequest = new HttpRequestMessage(HttpMethod.Post, "/api/v1/agents/register")
        {
            Content = JsonContent.Create(req, options: JsonOpts),
        };
        using var deadline = AgentHttpFailure.CreateDeadline(_http, ct);
        using var resp = await _http.SendAsync(
            registerRequest,
            HttpCompletionOption.ResponseHeadersRead,
            deadline.Token).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw await AgentHttpFailure.CreateAsync("Register", resp, _http, ct, deadline.Token).ConfigureAwait(false);

        var body = await AgentHttpFailure.ReadBodyAsStringAsync(
            "Register",
            resp,
            _http,
            ct,
            deadline.Token).ConfigureAwait(false);
        var parsed = JsonSerializer.Deserialize<AgentRegisterResponse>(body, JsonOpts);
        if (parsed is null || string.IsNullOrWhiteSpace(parsed.AgentId) || string.IsNullOrWhiteSpace(parsed.TenantId))
            throw new InvalidOperationException("Register response missing agent_id/tenant_id.");

        var identity = new AgentIdentity(parsed.AgentId, parsed.TenantId);
        await _secrets.SaveAsync(
            identity,
            parsed.AgentRefreshToken,
            privPem,
            string.IsNullOrWhiteSpace(parsed.TelemetryBaseUrl) ? backendUrlForStorage : parsed.TelemetryBaseUrl.TrimEnd('/'),
            parsed.TailscaleLoginServer,
            parsed.TailscaleAuthkey,
            ct).ConfigureAwait(false);
        await AgentUiContextStore.WriteBestEffortAsync(
            identity,
            parsed.TenantName,
            accountLabel: null,
            ct).ConfigureAwait(false);

        await WriteTailscaleProofFileAsync(identity, parsed.TailscaleLoginServer, parsed.TailscaleAuthkey, ct).ConfigureAwait(false);

        _log.Info($"Registered agent_id={identity.AgentId} tenant_id={identity.TenantId}");
        return identity;
    }

    private async Task<AgentIdentity?> TryLoadExistingRegistrationAsync(CancellationToken ct)
    {
        try
        {
            var (identity, refreshToken, privateKeyPem, backendUrl, _, _) =
                await _secrets.LoadAsync(ct).ConfigureAwait(false);

            if (!string.IsNullOrWhiteSpace(identity.AgentId) &&
                !string.IsNullOrWhiteSpace(identity.TenantId) &&
                !string.IsNullOrWhiteSpace(refreshToken) &&
                !string.IsNullOrWhiteSpace(privateKeyPem) &&
                !string.IsNullOrWhiteSpace(backendUrl))
            {
                return identity;
            }

            throw new InvalidOperationException(
                "Existing agent registration is incomplete. Unregister or repair before registering again.");
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    private static async Task WriteTailscaleProofFileAsync(
        AgentIdentity identity,
        string? loginServer,
        string? authkey,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(loginServer) || string.IsNullOrWhiteSpace(authkey))
            return;

        // Write a non-sensitive "proof" file: never store the authkey in plaintext.
        // Proof file is non-sensitive, but keep it user-scope so onboarding does not require admin/UAC.
        var baseDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CerberusAgent");
        Directory.CreateDirectory(baseDir);

        var proofPath = Path.Combine(baseDir, "tailscale_preauth_proof.json");
        var authkeyBytes = System.Text.Encoding.UTF8.GetBytes(authkey.Trim());
        var hashHex = Convert.ToHexString(SHA256.HashData(authkeyBytes)).ToLowerInvariant();
        var last4 = authkey.Trim().Length >= 4 ? authkey.Trim()[^4..] : authkey.Trim();

        var proof = new
        {
            agent_id = identity.AgentId,
            tenant_id = identity.TenantId,
            tailscale_login_server = loginServer.Trim(),
            tailscale_authkey_sha256 = hashHex,
            tailscale_authkey_last4 = last4,
            created_at_utc = DateTimeOffset.UtcNow.ToString("O"),
            note = "Proof that preauth key was received. Key value is not stored here.",
        };

        await File.WriteAllTextAsync(
            proofPath,
            JsonSerializer.Serialize(proof, JsonOpts),
            System.Text.Encoding.UTF8,
            ct);
    }

    private sealed record AgentRegisterRequest(
        [property: JsonPropertyName("oauth_token")] string OauthToken,
        [property: JsonPropertyName("agent_public_key_pem")] string AgentPublicKeyPem,
        [property: JsonPropertyName("device_fingerprint")] string DeviceFingerprint,
        [property: JsonPropertyName("agent_version")] string AgentVersion,
        [property: JsonPropertyName("build_id")] string BuildId,
        [property: JsonPropertyName("build_channel")] string BuildChannel,
        [property: JsonPropertyName("supported_schema_versions")] IReadOnlyList<string> SupportedSchemaVersions,
        [property: JsonPropertyName("display_name")] string DisplayName,
        [property: JsonPropertyName("purpose_note")] string? PurposeNote,
        [property: JsonPropertyName("location_hint")] string? LocationHint);

    private sealed record AgentRegisterResponse(
        [property: JsonPropertyName("agent_id")] string AgentId,
        [property: JsonPropertyName("tenant_id")] string TenantId,
        [property: JsonPropertyName("tenant_name")] string? TenantName,
        [property: JsonPropertyName("tailscale_login_server")] string? TailscaleLoginServer,
        [property: JsonPropertyName("tailscale_authkey")] string? TailscaleAuthkey,
        [property: JsonPropertyName("agent_refresh_token")] string AgentRefreshToken,
        [property: JsonPropertyName("agent_access_token")] string? AgentAccessToken,
        [property: JsonPropertyName("jwt_public_key_pem")] string? JwtPublicKeyPem,
        [property: JsonPropertyName("telemetry_base_url")] string? TelemetryBaseUrl,
        [property: JsonPropertyName("version_policy")] VersionPolicy? VersionPolicy);
}
