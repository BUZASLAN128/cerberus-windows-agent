using System.Text.Json;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentWakeupHandshakeTests
{
    private const string AgentId = "b9b71bb5-85d3-4d88-a207-88548bc9ba38";

    [Fact]
    public async Task Handshake_SignsEmptyGetForCurrentAgentAndOrigin()
    {
        var signer = new CaptureSigner();
        using var http = new HttpClient { BaseAddress = new Uri("https://collector.example:8443") };
        var client = new AgentApiClient(http, new FakeSecrets(), new FakeToken(), signer);
        using var json = JsonDocument.Parse($"{{\"version\":1,\"path\":\"/api/v1/agents/{AgentId}/wakeup\"}}");
        var (endpoint, request) = await client.BuildWakeupHandshakeAsync(json.RootElement, default);
        using (request)
        {
            Assert.Equal("wss://collector.example:8443/api/v1/agents/" + AgentId + "/wakeup", endpoint.AbsoluteUri);
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal(0, (await request.Content!.ReadAsByteArrayAsync()).Length);
            Assert.Equal("GET", signer.Method);
            Assert.Equal($"/api/v1/agents/{AgentId}/wakeup", signer.Path);
            Assert.Equal(0, signer.BodyLength);
            Assert.Equal(AgentId, request.Headers.GetValues("X-Agent-Id").Single());
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
        }
    }

    [Theory]
    [InlineData("/api/v1/agents/another/wakeup")]
    [InlineData("//other.example/api/v1/agents/x/wakeup")]
    public async Task Handshake_RejectsWrongAgentOrOriginBeforeTokenOrSignature(string path)
    {
        var signer = new CaptureSigner();
        var token = new FakeToken();
        using var http = new HttpClient { BaseAddress = new Uri("https://collector.example") };
        var client = new AgentApiClient(http, new FakeSecrets(), token, signer);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(new { version = 1, path }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.BuildWakeupHandshakeAsync(json.RootElement, default));
        Assert.Equal(0, token.Calls);
        Assert.Null(signer.Method);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task Connection_DenialPreservesHttpsAuthorityAndRetryHint(HttpStatusCode status)
    {
        var handler = new LimitedUpgradeHandler(status);
        using var http = new HttpClient { BaseAddress = new Uri("https://collector.example") };
        var secrets = new FakeSecrets();
        var tokens = new FakeToken();
        var lifecycle = new InMemoryAgentLifecycleStateStore();
        var client = new AgentApiClient(http, secrets, tokens, new CaptureSigner(), lifecycle)
        {
            WakeupInvokerFactory = () => new HttpMessageInvoker(handler, disposeHandler: false),
        };
        using var json = JsonDocument.Parse($"{{\"version\":1,\"path\":\"/api/v1/agents/{AgentId}/wakeup\"}}");
        if (status == HttpStatusCode.TooManyRequests)
        {
            var failure = await Assert.ThrowsAsync<WakeupRateLimitedException>(() =>
                client.ListenForWakeupsOnceAsync(json.RootElement, new AgentWakeupSignal(), default));
            Assert.Equal(TimeSpan.FromSeconds(7200), failure.RetryAfter);
        }
        else
            await Assert.ThrowsAsync<WakeupRejectedException>(() =>
                client.ListenForWakeupsOnceAsync(json.RootElement, new AgentWakeupSignal(), default));
        Assert.Equal(1, handler.Attempts);
        Assert.Equal(HttpMethod.Get, handler.Method);
        Assert.Equal($"/api/v1/agents/{AgentId}/wakeup", handler.Path);
        Assert.Equal(AgentId, handler.AgentId);
        Assert.True(handler.HasAuthorization);
        Assert.Equal(0, secrets.Clears);
        Assert.Equal(0, tokens.Refreshes);
        Assert.Equal(AgentLifecycleState.Active, (await lifecycle.LoadAsync(default)).State);
    }

    [Fact]
    public async Task Connection_AcceptsBoundedHintOverWebSocketUpgrade()
    {
        var handler = new UpgradeHandler();
        using var http = new HttpClient { BaseAddress = new Uri("https://collector.example") };
        var client = new AgentApiClient(http, new FakeSecrets(), new FakeToken(), new CaptureSigner())
        {
            WakeupInvokerFactory = () => new HttpMessageInvoker(handler, disposeHandler: false),
        };
        using var json = JsonDocument.Parse($"{{\"version\":1,\"path\":\"/api/v1/agents/{AgentId}/wakeup\"}}");
        var signal = new AgentWakeupSignal();
        await client.ListenForWakeupsOnceAsync(json.RootElement, signal, default);
        Assert.True(await signal.WaitAsync(TimeSpan.Zero, default));
        Assert.Equal(1, handler.Attempts);
    }

    private sealed class UpgradeHandler : HttpMessageHandler
    {
        public int Attempts { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Attempts++;
            var key = request.Headers.GetValues("Sec-WebSocket-Key").Single();
            var accept = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            var payload = Encoding.UTF8.GetBytes("{\"type\":\"command_available\",\"version\":1}");
            var wire = new byte[payload.Length + 6];
            wire[0] = 0x81;
            wire[1] = (byte)payload.Length;
            payload.CopyTo(wire, 2);
            wire[^4] = 0x88;
            wire[^3] = 0x02;
            wire[^2] = 0x03;
            wire[^1] = 0xe8;
            var response = new HttpResponseMessage(HttpStatusCode.SwitchingProtocols)
            {
                Version = HttpVersion.Version11,
                Content = new UpgradeContent(new MemoryStream(wire, 0, wire.Length, writable: true, publiclyVisible: true)),
            };
            response.Headers.TryAddWithoutValidation("Connection", "Upgrade");
            response.Headers.TryAddWithoutValidation("Upgrade", "websocket");
            response.Headers.TryAddWithoutValidation("Sec-WebSocket-Accept", accept);
            return Task.FromResult(response);
        }
    }

    private sealed class UpgradeContent(Stream stream) : HttpContent
    {
        protected override Stream CreateContentReadStream(CancellationToken cancellationToken) => stream;
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult(stream);
        protected override Task SerializeToStreamAsync(Stream target, TransportContext? context)
            => throw new NotSupportedException();
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }

    private sealed class LimitedUpgradeHandler(HttpStatusCode status = HttpStatusCode.TooManyRequests) : HttpMessageHandler
    {
        public int Attempts { get; private set; }
        public HttpMethod? Method { get; private set; }
        public string? Path { get; private set; }
        public string? AgentId { get; private set; }
        public bool HasAuthorization { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Attempts++;
            Method = request.Method;
            Path = request.RequestUri!.AbsolutePath;
            AgentId = request.Headers.GetValues("X-Agent-Id").Single();
            HasAuthorization = request.Headers.Authorization?.Scheme == "Bearer";
            var response = new HttpResponseMessage(status);
            response.Headers.TryAddWithoutValidation("Retry-After", "7200");
            return Task.FromResult(response);
        }
    }

    private sealed class FakeSecrets : ISecretStore
    {
        public int Clears { get; private set; }
        public Task<(AgentIdentity, string, string, string, string?, string?)> LoadAsync(CancellationToken ct)
            => Task.FromResult<(AgentIdentity, string, string, string, string?, string?)>((new(AgentId, "tenant"), "r", "k", "https://collector.example", null, null));
        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) { Clears++; return Task.CompletedTask; }
    }

    private sealed class FakeToken : ITokenManager
    {
        public int Calls { get; private set; }
        public int Refreshes { get; private set; }
        public Task<string> GetAccessTokenAsync(CancellationToken ct) { Calls++; return Task.FromResult("test-token"); }
        public Task RefreshAsync(CancellationToken ct) { Refreshes++; return Task.CompletedTask; }
    }

    private sealed class CaptureSigner : IRequestSigner
    {
        public string? Method { get; private set; }
        public string? Path { get; private set; }
        public int BodyLength { get; private set; } = -1;
        public string ComputeBodyHash(byte[] bodyBytes) { BodyLength = bodyBytes.Length; return "hash"; }
        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash) { Method = method; Path = path; return "canonical"; }
        public string Sign(string canonical) => "signature";
    }
}
