using System.Net;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentApiClientTelemetryTests
{
    [Fact]
    public async Task SubmitSnapshotAsync_PostsSignedSnapshotEndpoint()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var snapshot = AgentSnapshotFactory.Create(
            Metadata(),
            DateTimeOffset.Parse("2026-05-07T00:00:00Z"),
            new Dictionary<string, object?> { ["identity"] = new { status = "ok" } });

        var ack = await client.SubmitSnapshotAsync(snapshot, CancellationToken.None);

        Assert.Equal("accepted", ack.Status);
        Assert.Equal("/api/v1/agents/a1/snapshot", handler.CapturedRequest!.RequestUri!.AbsolutePath);
        Assert.Contains("X-Signature", handler.CapturedRequest.Headers.Select(h => h.Key));
        using var doc = JsonDocument.Parse(handler.CapturedBody!);
        Assert.Equal(AgentSchemaVersions.Snapshot, doc.RootElement.GetProperty("schema_version").GetString());
    }

    [Fact]
    public async Task SubmitEventsAndProbeResult_PostExpectedEndpoints()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var events = AgentTelemetryFactory.CreateEvents(
            Metadata(),
            new[]
            {
                new AgentEventItem(
                    EventId: "evt-12345678",
                    Type: "agent.started",
                    OccurredAt: "2026-05-07T00:00:00Z",
                    Severity: "info",
                    Payload: new Dictionary<string, object?>()),
            });
        await client.SubmitEventsAsync(events, CancellationToken.None);
        Assert.Equal("/api/v1/agents/a1/events", handler.CapturedRequest!.RequestUri!.AbsolutePath);

        var probe = AgentTelemetryFactory.CreateProbeResult(
            Metadata(),
            resultId: "res-12345678",
            probeId: "agent.self_test",
            status: "ok",
            payload: new Dictionary<string, object?>());
        await client.SubmitProbeResultAsync(probe, CancellationToken.None);
        Assert.Equal("/api/v1/agents/a1/probe-results", handler.CapturedRequest!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SelfDeactivateAsync_PostsSignedDeactivateEndpoint()
    {
        var handler = new CaptureHandler(
            """{"status":"deactivated","agent_id":"a1","registration_state":"deactivated","revoked_tokens":1}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var response = await client.SelfDeactivateAsync(
            new AgentSelfDeactivateRequest(
                SchemaVersion: "agent.self-deactivate.v1",
                ReasonCode: "agent_unregister_device",
                Reason: "unit"),
            CancellationToken.None);

        Assert.Equal("deactivated", response.Status);
        Assert.Equal(1, response.RevokedTokens);
        Assert.Equal("/api/v1/agents/a1/deactivate", handler.CapturedRequest!.RequestUri!.AbsolutePath);
        Assert.Contains("X-Signature", handler.CapturedRequest.Headers.Select(h => h.Key));
        using var doc = JsonDocument.Parse(handler.CapturedBody!);
        Assert.Equal("agent.self-deactivate.v1", doc.RootElement.GetProperty("schema_version").GetString());
        Assert.Equal("agent_unregister_device", doc.RootElement.GetProperty("reason_code").GetString());
    }

    private static AgentBuildMetadata Metadata() => new(
        AgentVersion: "1.2.3",
        BuildId: "build-1",
        BuildChannel: "dev",
        BootId: "boot-1",
        SupportedSchemaVersions: AgentSchemaVersions.All);

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly string _responseBody;

        public CaptureHandler(string? responseBody = null)
        {
            _responseBody = responseBody
                ?? """{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":["identity"]}""";
        }

        public HttpRequestMessage? CapturedRequest { get; private set; }
        public string? CapturedBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedRequest = request;
            CapturedBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    _responseBody,
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }

    private sealed class StaticSecretStore : ISecretStore
    {
        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct) => Task.CompletedTask;

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            return Task.FromResult((
                new AgentIdentity("a1", "t1"),
                "refresh",
                "private",
                "http://backend.test",
                (string?)null,
                (string?)null));
        }

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StaticTokenManager : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("token");
        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StaticSigner : IRequestSigner
    {
        public string ComputeBodyHash(byte[] bodyBytes) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bodyBytes)).ToLowerInvariant();
        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash) => $"{method}:{path}:{nonce}:{timestamp}:{bodyHash}";
        public string Sign(string canonical) => "signature";
    }
}
