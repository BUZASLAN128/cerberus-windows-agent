using System.Net;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentIdentityWakeupTests
{
    [Fact]
    public async Task WebSocketUpgradeCopiesAuthorityBoundSignatureForSecondaryTarget()
    {
        using var signer = new RequestSigner(IdentityTestKey.PrivateKeyPem);
        using var http = new HttpClient { BaseAddress = new Uri("https://SECONDARY.example:8443") };
        var handler = new CaptureUpgrade();
        var client = new AgentApiClient(http, new Store(), new Tokens(), signer)
        {
            WakeupInvokerFactory = () => new HttpMessageInvoker(handler, disposeHandler: false),
        };
        using var discovery = JsonDocument.Parse("""{"version":1,"path":"/api/v1/agents/identity/wakeup"}""");
        await Assert.ThrowsAsync<WakeupRejectedException>(() =>
            client.ListenForWakeupsOnceAsync(discovery.RootElement, new AgentWakeupSignal(), default));
        Assert.True(handler.Verified);
    }

    private sealed class CaptureUpgrade : HttpMessageHandler
    {
        public bool Verified;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            AgentIdentitySigningTests.Verify(request, [], "secondary.example:8443");
            Verified = true;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden));
        }
    }

    private sealed class Tokens : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("test-access");
        public Task RefreshAsync(CancellationToken ct) => throw new InvalidOperationException("Unexpected refresh");
    }

    private sealed class Store : ISecretStore
    {
        public Task<(AgentIdentity, string, string, string, string?, string?)> LoadAsync(CancellationToken ct)
            => Task.FromResult<(AgentIdentity, string, string, string, string?, string?)>((new("identity", "tenant", AgentProducts.Secondary),
                "test-refresh", IdentityTestKey.PrivateKeyPem, "https://secondary.example:8443", null, null));
        public Task SaveAsync(AgentIdentity id, string refresh, string key, string backend, string? login, string? auth, CancellationToken ct)
            => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
