using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentWakeupClientTests
{
    [Fact]
    public async Task ReconfigurationKeepsRateLimitDeadlineAndStopsOnMissingDiscovery()
    {
        using var http = new HttpClient { BaseAddress = new Uri("https://agent.example") };
        var api = new AgentApiClient(http, new FakeSecrets(), new FakeToken(), new FakeSigner());
        var signal = new AgentWakeupSignal();
        var called = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        Task Listen(JsonElement _, AgentWakeupSignal __, CancellationToken ___)
        {
            Interlocked.Increment(ref calls);
            called.TrySetResult();
            throw new WakeupRateLimitedException(TimeSpan.FromMinutes(1));
        }
        await using var client = new AgentWakeupClient(api, signal, Listen);
        using var json = JsonDocument.Parse("{\"version\":1,\"path\":\"/api/ws\"}");
        await client.ConfigureAsync(json.RootElement, default);
        await called.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await client.ConfigureAsync(null, default);
        await client.ConfigureAsync(json.RootElement, default);
        await Task.Delay(100);
        Assert.Equal(1, Volatile.Read(ref calls));
        await client.StopAsync(default);
    }

    [Fact]
    public async Task VeryLongRetryAfterRemainsCancellableWithoutDelayOverflow()
    {
        using var http = new HttpClient { BaseAddress = new Uri("https://agent.example") };
        var api = new AgentApiClient(http, new FakeSecrets(), new FakeToken(), new FakeSigner());
        var called = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var log = new RecordingLogger();
        Task Listen(JsonElement _, AgentWakeupSignal __, CancellationToken ___)
        {
            Interlocked.Increment(ref calls);
            called.TrySetResult();
            throw new WakeupRateLimitedException(TimeSpan.MaxValue);
        }
        await using var client = new AgentWakeupClient(api, new AgentWakeupSignal(), Listen, log);
        using var json = JsonDocument.Parse("{\"version\":1,\"path\":\"/api/ws\"}");
        await client.ConfigureAsync(json.RootElement, default);
        await called.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await client.ConfigureAsync(null, default);
        await client.ConfigureAsync(json.RootElement, default);
        await Task.Delay(100);
        Assert.Equal(1, Volatile.Read(ref calls));
        Assert.Empty(log.Lines);
        await client.StopAsync(default);
    }

    [Fact]
    public async Task InvalidDiscoveryNeverStartsConnection()
    {
        using var http = new HttpClient { BaseAddress = new Uri("https://agent.example") };
        var api = new AgentApiClient(http, new FakeSecrets(), new FakeToken(), new FakeSigner());
        var called = 0;
        Task Listen(JsonElement _, AgentWakeupSignal __, CancellationToken ___) { called++; return Task.CompletedTask; }
        await using var client = new AgentWakeupClient(api, new AgentWakeupSignal(), Listen);
        using var json = JsonDocument.Parse("{\"version\":1,\"path\":\"//evil.example/ws\"}");
        await client.ConfigureAsync(json.RootElement, default);
        Assert.Equal(0, called);
    }

    [Fact]
    public async Task AmbiguousForbiddenDoesNotReconnectOnTheNextHeartbeat()
    {
        using var http = new HttpClient { BaseAddress = new Uri("https://agent.example") };
        var api = new AgentApiClient(http, new FakeSecrets(), new FakeToken(), new FakeSigner());
        var called = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        Task Listen(JsonElement _, AgentWakeupSignal __, CancellationToken ___)
        {
            Interlocked.Increment(ref calls);
            called.TrySetResult();
            throw new WakeupRejectedException();
        }
        await using var client = new AgentWakeupClient(api, new AgentWakeupSignal(), Listen);
        using var json = JsonDocument.Parse("{\"version\":1,\"path\":\"/api/ws\"}");
        await client.ConfigureAsync(json.RootElement, default);
        await called.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await client.ConfigureAsync(json.RootElement, default);
        await Task.Delay(100);
        Assert.Equal(1, Volatile.Read(ref calls));
    }

    private sealed class FakeSecrets : ISecretStore
    {
        public Task<(AgentIdentity, string, string, string, string?, string?)> LoadAsync(CancellationToken ct)
            => Task.FromResult<(AgentIdentity, string, string, string, string?, string?)>((new("agent", "tenant"), "", "", "https://agent.example", null, null));
        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
    private sealed class FakeToken : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("test");
        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }
    private sealed class FakeSigner : IRequestSigner
    {
        public string ComputeBodyHash(byte[] bodyBytes) => "hash";
        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash) => "canonical";
        public string Sign(string canonical) => "signature";
    }
}
