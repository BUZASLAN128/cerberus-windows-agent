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
