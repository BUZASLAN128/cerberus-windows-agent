using System.Net;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    [Theory]
    [InlineData(200, false, false, 3600, 1d, 300)] // successful next_poll
    [InlineData(429, false, false, 3600, 1d, 300)]
    [InlineData(429, false, false, 3600, 0d, 225)]
    [InlineData(429, false, false, 300, 1d, 300)]
    [InlineData(429, false, false, 300, 0d, 225)]
    [InlineData(429, false, false, 120, 1d, 144)]
    [InlineData(429, false, false, 120, 0d, 120)]
    [InlineData(503, false, false, 3600, 1d, 300)] // exponential error backoff
    [InlineData(429, true, false, 3600, 1d, 300)]  // actual token refresh
    [InlineData(200, false, true, 3600, 1d, 300)]  // old persisted retry
    public async Task CollectorContactWaitNeverExceedsCompiledCeiling(int firstStatus, bool refresh, bool persisted,
        int retryAfter, double jitter, int expectedSeconds)
    {
        var clock = new FakeTime(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var startedAt = clock.Now;
        var ceiling = TimeSpan.FromSeconds(AgentTimingPolicy.Current.Bounds.PollCeiling);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var wire = new ContactDelayCollector(firstStatus, refresh, clock, retryAfter);
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        ISecretStore secrets = refresh ? new RefreshContactSecrets() : new StaticSecretStore();
        ITokenManager tokens = refresh ? new AgentTokenManager(http, secrets) : new StaticTokenManager();
        var state = new InMemoryAgentLifecycleStateStore(new AgentLifecycleSnapshot
        {
            NextAttemptUtc = persisted ? clock.Now.AddHours(1) : null,
        });
        var api = new AgentApiClient(http, secrets, tokens, new StaticSigner(), state);
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "idem.json"), 10, ceiling));
        var signal = new AgentWakeupSignal();
        var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromHours(1), lifecycleState: state,
            supportsEvents: false, wakeupSignal: firstStatus == 200 ? null : signal, timeProvider: clock, retryJitter: () => jitter);
        var run = loop.RunAsync(stop.Token);
        try
        {
            await Wait.UntilAsync(() => clock.ActiveTimerCount > 0, "contact delay scheduled");
            var initialContacts = persisted ? 0 : 1;
            Assert.Equal(initialContacts, wire.Contacts);
            signal.Signal();
            signal.Signal();
            await Task.Yield();
            Assert.Equal(initialContacts, wire.Contacts); // hints do not bypass rate limiting
            if (firstStatus == 429 || persisted)
            {
                clock.Advance(TimeSpan.FromSeconds(expectedSeconds - 1));
                await Task.Yield();
                Assert.Equal(initialContacts, wire.Contacts);
                clock.Advance(TimeSpan.FromSeconds(1));
            }
            else clock.Advance(ceiling);
            await Wait.UntilAsync(() => wire.Contacts > initialContacts, "next collector contact within ceiling");
            Assert.InRange(wire.LastContactAt!.Value - startedAt, TimeSpan.Zero, ceiling);
        }
        finally
        {
            stop.Cancel();
            await run;
        }
    }

    [Fact]
    public async Task TokenRefresh429_RestartHeartbeatResumesAtPersistedClippedDeadline()
    {
        var clock = new FakeTime(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var startedAt = clock.Now;
        var fullDeadline = startedAt.AddSeconds(600);
        var ceiling = TimeSpan.FromSeconds(AgentTimingPolicy.Current.Bounds.PollCeiling);
        var wire = new ContactDelayCollector(429, refresh: true, clock, retryAfter: 600);
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var secrets = new RefreshContactSecrets();
        var store = new InMemoryAgentLifecycleStateStore();
        var root = Path.Combine(Path.GetTempPath(), "cerberus-heartbeat-restart-" + Guid.NewGuid().ToString("N"));
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(root, "idem.json"), 10, ceiling));

        AgentTokenManager NewTokens() => new(http, secrets, utcNow: () => clock.Now, lifecycleState: store,
            accessTokenCache: new AgentAccessTokenCache(Path.Combine(root, "cache"), production: false));
        HeartbeatLoop NewLoop(AgentTokenManager tokens) => new(
            new AgentApiClient(http, secrets, tokens, new StaticSigner(), store), dispatcher, TimeSpan.FromHours(1),
            lifecycleState: store, supportsEvents: false, timeProvider: clock, retryJitter: () => 1d);

        try
        {
            var tokens = NewTokens();
            using var beforeRestart = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var firstRun = NewLoop(tokens).RunAsync(beforeRestart.Token);
            DateTimeOffset persisted;
            try
            {
                await Wait.UntilAsync(() => clock.ActiveTimerCount > 0, "first heartbeat retry scheduled");
                Assert.Equal(1, wire.Contacts);
                var gated = await Assert.ThrowsAsync<AgentHttpException>(() => tokens.RefreshAsync(beforeRestart.Token));
                Assert.Equal(fullDeadline, clock.Now + Assert.IsType<TimeSpan>(gated.RetryAfter));
                persisted = Assert.IsType<DateTimeOffset>((await store.LoadAsync(beforeRestart.Token)).NextAttemptUtc);
                Assert.Equal(startedAt + ceiling, persisted);
                Assert.True(persisted < fullDeadline);
            }
            finally
            {
                beforeRestart.Cancel();
                await firstRun;
            }

            clock.Advance(TimeSpan.FromSeconds(30));
            var restartAt = clock.Now;
            var restartDeadline = persisted < restartAt + ceiling ? persisted : restartAt + ceiling;
            using var afterRestart = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var restarted = NewLoop(NewTokens()).RunAsync(afterRestart.Token);
            try
            {
                await Wait.UntilAsync(() => clock.ActiveTimerCount > 0, "restarted heartbeat retry scheduled");
                clock.Advance(restartDeadline - restartAt - TimeSpan.FromSeconds(1));
                Assert.Equal(1, wire.Contacts);
                clock.Advance(TimeSpan.FromSeconds(1));
                await Wait.UntilAsync(() => wire.Contacts == 2, "restarted heartbeat contacts token route");
                Assert.Equal(restartDeadline, wire.LastContactAt);
            }
            finally
            {
                afterRestart.Cancel();
                await restarted;
            }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private sealed class ContactDelayCollector(int status, bool refresh, FakeTime clock, int retryAfter) : HttpMessageHandler
    {
        private int _contacts;
        public int Contacts => Volatile.Read(ref _contacts);
        public DateTimeOffset? LastContactAt { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var isContact = request.RequestUri!.AbsolutePath.EndsWith(refresh ? "/token" : "/heartbeat", StringComparison.Ordinal);
            if (isContact) LastContactAt = clock.Now;
            var count = isContact ? Interlocked.Increment(ref _contacts) : 0;
            var response = new HttpResponseMessage(count == 1 ? (HttpStatusCode)status : HttpStatusCode.OK)
            {
                Content = new StringContent(request.RequestUri.AbsolutePath.EndsWith("/token", StringComparison.Ordinal)
                    ? """{"access_token":"fixture","expires_in":300}"""
                    : """{"pending_commands":[],"next_poll_seconds":3600,"next_snapshot_seconds":300,"server_time":1}"""),
            };
            if (count == 1 && status == 429) response.Headers.TryAddWithoutValidation("Retry-After", retryAfter.ToString(System.Globalization.CultureInfo.InvariantCulture));
            return Task.FromResult(response);
        }
    }

    private sealed class RefreshContactSecrets : ISecretStore
    {
        public Task<(AgentIdentity, string, string, string, string?, string?)> LoadAsync(CancellationToken ct)
            => Task.FromResult<(AgentIdentity, string, string, string, string?, string?)>((new("agent-1", "tenant-1"), "fixture",
                IdentityTestKey.PrivateKeyPem, "https://backend.test", null, null));
        public Task SaveAsync(AgentIdentity id, string refresh, string key, string url, string? login, string? auth, CancellationToken ct) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
