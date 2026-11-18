using System.Net;
using System.Text;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentTokenManagerTests
{
    [Fact]
    public async Task RestartReusesCachedToken_NoRefreshCall()
    {
        using var fixture = new AccessTokenFixture();
        Assert.Equal("access", await fixture.Manager().GetAccessTokenAsync(default));
        fixture.Now = fixture.Now.AddMinutes(9);

        Assert.Equal("access", await fixture.Manager().GetAccessTokenAsync(default));
        Assert.Equal(1, fixture.Handler.RequestCount);
    }

    [Fact]
    public async Task NonRotatingRefresh_WritesCache()
    {
        using var fixture = new AccessTokenFixture();

        Assert.Equal("access", await fixture.Manager().GetAccessTokenAsync(default));
        Assert.Null(fixture.Secrets.SavedRefreshToken);
        Assert.True(File.Exists(fixture.CachePath));
    }

    [Fact]
    public async Task RotatingRefresh_SecretsSavedThenCacheWritten()
    {
        using var fixture = new AccessTokenFixture();
        fixture.Handler.Respond = _ => Task.FromResult(TokenResponse("access", "rotated"));
        fixture.Secrets.OnSave = () => Assert.False(File.Exists(fixture.CachePath));

        Assert.Equal("access", await fixture.Manager().GetAccessTokenAsync(default));
        Assert.Equal("rotated", fixture.Secrets.SavedRefreshToken);
        Assert.True(File.Exists(fixture.CachePath));
    }

    [Fact]
    public async Task GenerationChangeDuringRefresh_NoCacheWritten()
    {
        using var fixture = new AccessTokenFixture();
        fixture.Handler.Respond = async _ =>
        {
            await new AgentLifecycleController(fixture.State).CompleteEnrollmentAsync(0, Guid.NewGuid().ToString("N"), default);
            return TokenResponse("access");
        };

        await Assert.ThrowsAsync<AgentLifecycleDormantException>(() => fixture.Manager().GetAccessTokenAsync(default));
        Assert.False(File.Exists(fixture.CachePath));
    }

    [Fact]
    public async Task Unauthorized401_DeletesCacheBeforeRefresh()
    {
        using var fixture = new AccessTokenFixture();
        var manager = fixture.Manager();
        await manager.GetAccessTokenAsync(default);
        Assert.True(File.Exists(fixture.CachePath));
        fixture.Handler.Respond = _ =>
        {
            Assert.False(File.Exists(fixture.CachePath));
            Assert.True(Directory.Exists(Path.GetDirectoryName(fixture.CachePath)));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        };

        await Assert.ThrowsAnyAsync<HttpRequestException>(() => manager.RefreshAsync(default));
        Assert.Equal(2, fixture.Handler.RequestCount);
        Assert.False(File.Exists(fixture.CachePath));
    }

    [Fact]
    public async Task Refresh429_GatesAllCallersUntilRetryAfter_SingleNetworkCall()
    {
        using var fixture = new AccessTokenFixture();
        fixture.Handler.Respond = _ => Task.FromResult(RateLimitResponse("120"));
        var manager = fixture.Manager();
        var failure = await Assert.ThrowsAsync<AgentHttpException>(() => manager.GetAccessTokenAsync(default));
        var stateAfterResponse = await fixture.State.LoadAsync(default);
        Assert.Equal(TimeSpan.FromSeconds(120), failure.RetryAfter);
        Assert.Equal(AgentLifecycleState.Degraded, stateAfterResponse.State);
        fixture.Now = fixture.Now.AddSeconds(10);

        var gated = await Task.WhenAll(
            Assert.ThrowsAsync<AgentHttpException>(() => manager.RefreshAsync(default)),
            Assert.ThrowsAsync<AgentHttpException>(() => manager.GetAccessTokenAsync(default)));
        Assert.All(gated, ex =>
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, ex.StatusCode);
            Assert.Equal(TimeSpan.FromSeconds(110), ex.RetryAfter);
        });
        Assert.Equal(1, fixture.Handler.RequestCount);
        Assert.Equal(stateAfterResponse, await fixture.State.LoadAsync(default));

        fixture.Now = fixture.Now.AddSeconds(110);
        fixture.Handler.Respond = _ => Task.FromResult(TokenResponse("restored"));
        Assert.Equal("restored", await manager.GetAccessTokenAsync(default));
        Assert.Equal(2, fixture.Handler.RequestCount);
    }

    [Theory]
    [InlineData("600", 600)]
    [InlineData("7200", 3600)]
    [InlineData("0", 5)]
    [InlineData(null, 60)]
    public async Task Refresh429_RetryAfter600Honoured_Cap1h(string? header, int seconds)
    {
        using var fixture = new AccessTokenFixture();
        fixture.Handler.Respond = _ => Task.FromResult(RateLimitResponse(header));
        var manager = fixture.Manager();
        await Assert.ThrowsAsync<AgentHttpException>(() => manager.RefreshAsync(default));
        fixture.Now = fixture.Now.AddSeconds(seconds - 1);

        var blocked = await Assert.ThrowsAsync<AgentHttpException>(() => manager.RefreshAsync(default));
        Assert.Equal(TimeSpan.FromSeconds(1), blocked.RetryAfter);
        Assert.Equal(1, fixture.Handler.RequestCount);

        fixture.Now = fixture.Now.AddSeconds(1);
        fixture.Handler.Respond = _ => Task.FromResult(TokenResponse("access"));
        await manager.RefreshAsync(default);
        Assert.Equal(2, fixture.Handler.RequestCount);
    }

    [Fact]
    public async Task ManualManagerHasNoRefresh429Gate()
    {
        using var fixture = new AccessTokenFixture();
        fixture.Handler.Respond = _ => Task.FromResult(RateLimitResponse("120"));
        var manual = new AgentTokenManager(fixture.Http, fixture.Secrets);

        await Assert.ThrowsAsync<AgentHttpException>(() => manual.RefreshAsync(default));
        await Assert.ThrowsAsync<AgentHttpException>(() => manual.RefreshAsync(default));
        Assert.Equal(2, fixture.Handler.RequestCount);
    }

    [Fact]
    public async Task CacheWriteFailure_RefreshStillSucceeds()
    {
        using var fixture = new AccessTokenFixture();
        Directory.CreateDirectory(fixture.CachePath);

        Assert.Equal("access", await fixture.Manager().GetAccessTokenAsync(default));
        Assert.True(Directory.Exists(fixture.CachePath));
    }

    private static HttpResponseMessage TokenResponse(string token, string? rotated = null)
        => new(HttpStatusCode.OK)
        {
            Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(new
            {
                access_token = token,
                expires_in = 900,
                refresh_token = rotated,
            }), Encoding.UTF8, "application/json"),
        };

    private static HttpResponseMessage RateLimitResponse(string? delay)
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        if (delay is not null) response.Headers.TryAddWithoutValidation("Retry-After", delay);
        return response;
    }

    private sealed class AccessTokenFixture : IDisposable
    {
        private readonly string _cacheDirectory = Path.Combine(Path.GetTempPath(), "cerberus-token-manager-" + Guid.NewGuid().ToString("N"));

        public AccessTokenFixture() => Http = new HttpClient(Handler) { BaseAddress = new Uri("http://backend.local") };

        public string CachePath => Path.Combine(_cacheDirectory, "access-token.v1.dpapi");
        public DateTimeOffset Now { get; set; } = new(2026, 11, 18, 12, 0, 0, TimeSpan.Zero);
        public ObservedSecretStore Secrets { get; } = new();
        public InMemoryAgentLifecycleStateStore State { get; } = new();
        public RateLimitHandler Handler { get; } = new();
        public HttpClient Http { get; }

        public AgentTokenManager Manager() => new(Http, Secrets, refreshSafetyMargin: TimeSpan.FromSeconds(90),
            utcNow: () => Now, lifecycleState: State, expectedGeneration: 0,
            accessTokenCache: new AgentAccessTokenCache(_cacheDirectory, production: false));

        public void Dispose()
        {
            Http.Dispose();
            if (Directory.Exists(_cacheDirectory)) Directory.Delete(_cacheDirectory, recursive: true);
        }
    }

    private sealed class ObservedSecretStore : ISecretStore
    {
        private readonly CountingSecretStore _inner = new();
        public Action? OnSave { get; set; }
        public string? SavedRefreshToken => _inner.Saves.SingleOrDefault().RefreshToken;

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl,
            string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => _inner.LoadAsync(ct);

        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
        {
            OnSave?.Invoke();
            return _inner.SaveAsync(identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey, ct);
        }

        public Task ClearAsync(CancellationToken ct) => _inner.ClearAsync(ct);
    }

    private sealed class RateLimitHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, Task<HttpResponseMessage>> Respond { get; set; } = _ => Task.FromResult(TokenResponse("access"));
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal("/api/v1/agents/token", request.RequestUri?.AbsolutePath);
            RequestCount++;
            return Respond(request);
        }
    }
}
