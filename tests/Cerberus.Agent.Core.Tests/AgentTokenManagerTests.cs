using System.Net;
using System.Text;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentTokenManagerTests
{
    [Fact]
    public async Task RefreshAsync_WithRotatedRefreshToken_LoadsSecretsOnce()
    {
        var store = new CountingSecretStore();
        using var http = new HttpClient(new JsonHandler(
            """{"access_token":"new-access","expires_in":300,"refresh_token":"rotated-refresh"}"""))
        {
            BaseAddress = new Uri("http://backend.local"),
        };
        var manager = new AgentTokenManager(http, store);

        await manager.RefreshAsync(CancellationToken.None);

        Assert.Equal(1, store.LoadCount);
        Assert.Single(store.Saves);
        Assert.Equal("rotated-refresh", store.Saves[0].RefreshToken);
        Assert.Equal("private-key", store.Saves[0].PrivateKeyPem);
        Assert.Equal("http://backend.local", store.Saves[0].BackendUrl);
    }

    private sealed class JsonHandler : HttpMessageHandler
    {
        private readonly string _json;

        public JsonHandler(string json)
        {
            _json = json;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_json, Encoding.UTF8, "application/json"),
            });
    }

    private sealed class CountingSecretStore : ISecretStore
    {
        public int LoadCount { get; private set; }
        public List<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl)> Saves { get; } = [];

        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct)
        {
            Saves.Add((identity, refreshToken, privateKeyPem, backendUrl));
            return Task.CompletedTask;
        }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)>
            LoadAsync(CancellationToken ct)
        {
            LoadCount++;
            return Task.FromResult((
                new AgentIdentity("agent-id", "tenant-id"),
                "old-refresh",
                "private-key",
                "http://backend.local",
                (string?)null,
                (string?)null));
        }

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
