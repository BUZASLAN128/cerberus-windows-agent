using System.Net;
using System.Text;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentTokenManagerTests
{
    [Fact]
    public async Task SecondaryTokenIsNeverSentToAnotherEndpoint()
    {
        var store = new ProductStore();
        var handler = new JsonHandler("""{"access_token":"fixture","expires_in":300}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://other.example") };
        var manager = new AgentTokenManager(http, store);
        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.GetAccessTokenAsync(default));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task SecondaryCachedTokenIsNotReturnedAfterProductChange()
    {
        var store = new ProductStore();
        var handler = new JsonHandler("""{"access_token":"fixture","expires_in":300}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://collector.example") };
        var manager = new AgentTokenManager(http, store);
        Assert.Equal("fixture", await manager.GetAccessTokenAsync(default));
        store.Identity = store.Identity with { Product = AgentProducts.Cerberus };
        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.GetAccessTokenAsync(default));
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task PrimaryCachedTokenIsNotReturnedAfterProductChange()
    {
        var store = new ProductStore { Identity = new("agent", "tenant", AgentProducts.Cerberus) };
        var handler = new JsonHandler("""{"access_token":"fixture","expires_in":300}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://collector.example") };
        var manager = new AgentTokenManager(http, store);
        Assert.Equal("fixture", await manager.GetAccessTokenAsync(default));
        store.Identity = store.Identity with { Product = AgentProducts.Secondary };
        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.GetAccessTokenAsync(default));
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task PrimaryTokenIsNeverSentToAnotherEndpoint()
    {
        var store = new ProductStore { Identity = new("agent", "tenant", AgentProducts.Cerberus) };
        var handler = new JsonHandler("""{"access_token":"fixture","expires_in":300}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://other.example") };
        var manager = new AgentTokenManager(http, store);
        await Assert.ThrowsAsync<InvalidOperationException>(() => manager.GetAccessTokenAsync(default));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task CachedTokenIsNotReturnedAfterEnrollmentGenerationChanges()
    {
        var store = new ProductStore { Identity = new("agent", "tenant", AgentProducts.Cerberus) };
        var state = new InMemoryAgentLifecycleStateStore();
        var initial = await state.LoadAsync(default);
        var handler = new JsonHandler("""{"access_token":"fixture","expires_in":300}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://collector.example") };
        var manager = new AgentTokenManager(http, store, lifecycleState: state, expectedGeneration: initial.Generation);
        Assert.Equal("fixture", await manager.GetAccessTokenAsync(default));
        await new AgentLifecycleController(state).CompleteEnrollmentAsync(initial.Generation, Guid.NewGuid().ToString("N"), default);
        await Assert.ThrowsAsync<AgentLifecycleDormantException>(() => manager.GetAccessTokenAsync(default));
        Assert.Equal(1, handler.RequestCount);
    }

    private sealed class ProductStore : ISecretStore
    {
        public AgentIdentity Identity = new("agent", "tenant", AgentProducts.Secondary);
        public Task<(AgentIdentity, string, string, string, string?, string?)> LoadAsync(CancellationToken ct)
            => Task.FromResult<(AgentIdentity, string, string, string, string?, string?)>((Identity, "fixture", "key", "https://collector.example", null, null));
        public Task SaveAsync(AgentIdentity id, string refresh, string key, string url, string? login, string? auth, CancellationToken ct)
            => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
    [Fact]
    public async Task GetAccessTokenAsync_ReusesAccessTokenUntilSafetyMargin()
    {
        var store = new CountingSecretStore();
        var handler = new JsonHandler("""{"access_token":"short-lived-access","expires_in":300}""");
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://backend.local"),
        };
        var now = DateTimeOffset.Parse("2026-06-01T00:00:00Z");
        var manager = new AgentTokenManager(http, store, TimeSpan.FromSeconds(90), () => now);

        var first = await manager.GetAccessTokenAsync(CancellationToken.None);
        var second = await manager.GetAccessTokenAsync(CancellationToken.None);

        Assert.Equal("short-lived-access", first);
        Assert.Equal("short-lived-access", second);
        Assert.Equal(1, handler.RequestCount);
        Assert.Equal(2, store.LoadCount); // cached tokens recheck the active enrollment
        Assert.Empty(store.Saves);
    }

    [Fact]
    public async Task GetAccessTokenAsync_RefreshesInsideSafetyMargin()
    {
        var store = new CountingSecretStore();
        var handler = new QueueJsonHandler(
            """{"access_token":"first-access","expires_in":120}""",
            """{"access_token":"second-access","expires_in":120}""");
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://backend.local"),
        };
        var now = DateTimeOffset.Parse("2026-06-01T00:00:00Z");
        var manager = new AgentTokenManager(http, store, TimeSpan.FromSeconds(90), () => now);

        var first = await manager.GetAccessTokenAsync(CancellationToken.None);
        now = now.AddSeconds(40);
        var second = await manager.GetAccessTokenAsync(CancellationToken.None);

        Assert.Equal("first-access", first);
        Assert.Equal("second-access", second);
        Assert.Equal(2, handler.RequestCount);
        Assert.Equal(2, store.LoadCount);
    }

    [Fact]
    public async Task RefreshAsync_WithRotatedRefreshToken_LoadsSecretsOnce()
    {
        var store = new CountingSecretStore();
        var handler = new JsonHandler("""{"access_token":"new-access","expires_in":300,"refresh_token":"rotated-refresh"}""");
        using var http = new HttpClient(handler)
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

        public int RequestCount { get; private set; }

        public JsonHandler(string json)
        {
            _json = json;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_json, Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class QueueJsonHandler : HttpMessageHandler
    {
        private readonly Queue<string> _responses;

        public int RequestCount { get; private set; }

        public QueueJsonHandler(params string[] responses)
        {
            _responses = new Queue<string>(responses);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            var json = _responses.Count > 0 ? _responses.Dequeue() : """{"access_token":"fallback-access","expires_in":120}""";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            });
        }
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
