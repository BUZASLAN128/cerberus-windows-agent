using System.Net;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentRegistrarTests
{
    [Fact]
    public async Task RegisterAsync_BuildsExpectedRequest_AndStoresSecrets()
    {
        var handler = new CaptureHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """
                    {
                      "agent_id": "a1",
                      "tenant_id": "t1",
                      "tailscale_login_server": null,
                      "tailscale_authkey": null,
                      "agent_refresh_token": "rt1",
                      "agent_access_token": null,
                      "jwt_public_key_pem": null
                    }
                    """,
                    Encoding.UTF8,
                    "application/json"),
            });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };

        var secrets = new CaptureSecretStore();
        var keys = new StubKeyPairs("priv-pem", "pub-pem");

        var registrar = new AgentRegistrar(http, secrets, keys, log: NullAgentLogger.Instance);
        var identity = await registrar.RegisterAsync(
            oauthToken: "Bearer tok",
            backendUrlForStorage: "http://backend",
            deviceFingerprint: "fp",
            agentVersion: "1.2.3",
            ct: CancellationToken.None);

        Assert.Equal("a1", identity.AgentId);
        Assert.Equal("t1", identity.TenantId);

        Assert.NotNull(handler.CapturedRequest);
        Assert.Equal(HttpMethod.Post, handler.CapturedRequest!.Method);
        Assert.Equal("/api/v1/agents/register", handler.CapturedRequest!.RequestUri!.AbsolutePath);

        Assert.NotNull(handler.CapturedBody);
        using var doc = JsonDocument.Parse(handler.CapturedBody!);
        var root = doc.RootElement;

        Assert.Equal("Bearer tok", root.GetProperty("oauth_token").GetString());
        Assert.Equal("pub-pem", root.GetProperty("agent_public_key_pem").GetString());
        Assert.Equal("fp", root.GetProperty("device_fingerprint").GetString());
        Assert.Equal("1.2.3", root.GetProperty("agent_version").GetString());

        Assert.NotNull(secrets.LastSaved);
        Assert.Equal("a1", secrets.LastSaved!.Value.Identity.AgentId);
        Assert.Equal("t1", secrets.LastSaved!.Value.Identity.TenantId);
        Assert.Equal("rt1", secrets.LastSaved!.Value.RefreshToken);
        Assert.Equal("priv-pem", secrets.LastSaved!.Value.PrivateKeyPem);
        Assert.Equal("http://backend", secrets.LastSaved!.Value.BackendUrl);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public HttpRequestMessage? CapturedRequest { get; private set; }
        public string? CapturedBody { get; private set; }

        public CaptureHandler(HttpResponseMessage response)
        {
            _response = response;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedRequest = request;
            if (request.Content is not null)
                CapturedBody = await request.Content.ReadAsStringAsync(cancellationToken);
            return _response;
        }
    }

    private sealed class CaptureSecretStore : ISecretStore
    {
        public (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)? LastSaved { get; private set; }

        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct)
        {
            LastSaved = (identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey);
            return Task.CompletedTask;
        }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class StubKeyPairs : IKeyPairGenerator
    {
        private readonly string _priv;
        private readonly string _pub;

        public StubKeyPairs(string priv, string pub)
        {
            _priv = priv;
            _pub = pub;
        }

        public (string PrivateKeyPem, string PublicKeyPem) GenerateKeyPair(int keySize) => (_priv, _pub);
    }
}
