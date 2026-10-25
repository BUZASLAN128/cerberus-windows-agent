using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class HeadlessEnrollmentTests
{
    private const string AgentId = "agent-0001";

    [Theory]
    [InlineData(401, "{\"detail\":{\"code\":\"generic\"}}", 4)]
    [InlineData(401, "{\"detail\":{\"code\":\"agent_reenroll_required\"}}", 4)]
    [InlineData(401, "", 4)]
    [InlineData(403, "", 4)]
    [InlineData(403, "{\"detail\":{\"code\":\"forbidden\"}}", 4)]
    [InlineData(409, "{\"detail\":{\"code\":\"agent_proof_consumed\"}}", 4)]
    [InlineData(400, "{\"detail\":{\"code\":\"agent_exists\"}}", 4)]
    [InlineData(400, "{\"detail\":{\"code\":\"key_invalid\"}}", 3)]
    [InlineData(400, "{\"detail\":{\"code\":\"body_invalid\"}}", 3)]
    [InlineData(400, "{\"detail\":{\"code\":\"something_new\"}}", 3)]
    [InlineData(400, "not json", 3)]
    [InlineData(413, "", 3)]
    [InlineData(422, "", 3)]
    [InlineData(409, "{\"detail\":{\"code\":\"other\"}}", 3)]
    [InlineData(400, "{\"detail\":{\"code\":\"route_unavailable\"}}", 6)]
    [InlineData(404, "", 6)]
    public async Task Rejection_maps_to_exit_code_and_stores_nothing(int status, string body, int expectedExit)
    {
        var handler = new FakeHandler().Reply(status, body);
        var store = new MemoryStore();

        var result = await Run(handler, store);

        Assert.Equal(expectedExit, result.ExitCode);
        Assert.Equal(1, handler.Requests.Count);
        Assert.Equal(0, store.SaveCount);
    }

    [Fact]
    public async Task Success_saves_once_and_fingerprint_matches_the_saved_key()
    {
        var handler = new FakeHandler().Reply(200, SuccessBody());
        var store = new MemoryStore();

        var result = await Run(handler, store);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(1, store.SaveCount);
        var saved = store.Saved!.Value;
        Assert.Equal(AgentId, saved.Identity.AgentId);
        Assert.Equal("rt-secret", saved.RefreshToken);
        Assert.Equal("https://backend.example", saved.BackendUrl);
        Assert.Equal(AgentKeyFingerprint.FromPrivateKeyPem(saved.PrivateKeyPem), result.Fingerprint);
        Assert.Matches("^Agent key fingerprint=sha256:[0-9a-f]{64}$", HeadlessEnrollment.FormatFingerprintLine(result.Fingerprint!));

        var request = handler.Requests.Single();
        Assert.Equal(HeadlessEnrollment.Route, request.Path);
        Assert.Null(request.Authorization);
        using var doc = JsonDocument.Parse(request.Body);
        Assert.Equal(Proof(), doc.RootElement.GetProperty("enrollment_proof").GetString());
        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", doc.RootElement.GetProperty("agent_public_key_pem").GetString());
        Assert.DoesNotContain("PRIVATE", request.Body);
    }

    [Fact]
    public async Task Success_overwrites_the_previous_credentials_with_the_new_key()
    {
        var store = new MemoryStore { Saved = (new AgentIdentity("old-agent", "t0"), "old-rt", "OLD-KEY-PEM", "https://old", null, null) };

        var result = await Run(new FakeHandler().Reply(200, SuccessBody()), store,
            new AgentLifecycleSnapshot(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required"), hasCredentials: true);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(AgentId, store.Saved!.Value.Identity.AgentId);
        Assert.NotEqual("OLD-KEY-PEM", store.Saved.Value.PrivateKeyPem);
    }

    [Fact]
    public async Task Failed_run_leaves_the_previous_credentials_untouched()
    {
        var previous = (new AgentIdentity("old-agent", "t0"), "old-rt", "OLD-KEY-PEM", "https://old", (string?)null, (string?)null);
        var store = new MemoryStore { Saved = previous };

        var result = await Run(new FakeHandler().Reply(401, ""), store,
            new AgentLifecycleSnapshot(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required"), hasCredentials: true);

        Assert.Equal(4, result.ExitCode);
        Assert.Equal(previous, store.Saved);
        Assert.Equal(0, store.SaveCount);
    }

    [Fact]
    public async Task Retries_reuse_the_key_and_proof_within_one_run_with_default_delays()
    {
        var handler = new FakeHandler().Reply(503, "").Throw(new HttpRequestException("down")).Reply(200, SuccessBody());
        var time = new ImmediateTimeProvider();
        var store = new MemoryStore();

        var result = await Run(handler, store, time: time);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(3, handler.Requests.Count);
        Assert.Single(handler.Requests.Select(r => r.Body).Distinct());
        Assert.Equal([TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15)], time.Delays);
        Assert.Equal(1, store.SaveCount);
    }

    [Fact]
    public async Task Retry_after_is_honoured_and_capped_at_sixty_seconds()
    {
        var handler = new FakeHandler()
            .Reply(429, "", retryAfter: TimeSpan.FromSeconds(7))
            .Reply(503, "", retryAfter: TimeSpan.FromHours(1))
            .Reply(200, SuccessBody());
        var time = new ImmediateTimeProvider();

        var result = await Run(handler, new MemoryStore(), time: time);

        Assert.Equal(0, result.ExitCode);
        Assert.Equal([TimeSpan.FromSeconds(7), TimeSpan.FromSeconds(60)], time.Delays);
    }

    [Theory]
    [InlineData(429)]
    [InlineData(503)]
    public async Task Exhausted_retries_exit_five_after_three_attempts_and_store_nothing(int status)
    {
        var handler = new FakeHandler().Reply(status, "").Reply(status, "").Reply(status, "");
        var store = new MemoryStore();

        var result = await Run(handler, store);

        Assert.Equal(5, result.ExitCode);
        Assert.Equal(3, handler.Requests.Count);
        Assert.Equal(0, store.SaveCount);
    }

    [Fact]
    public async Task Transport_failures_exit_five()
    {
        var handler = new FakeHandler();
        for (var i = 0; i < 3; i++)
            handler.Throw(new HttpRequestException("down"));

        var result = await Run(handler, new MemoryStore());

        Assert.Equal(5, result.ExitCode);
        Assert.Equal(3, handler.Requests.Count);
    }

    [Fact]
    public async Task Every_run_sends_a_new_key()
    {
        var first = new FakeHandler().Reply(200, SuccessBody());
        var second = new FakeHandler().Reply(200, SuccessBody());

        await Run(first, new MemoryStore());
        await Run(second, new MemoryStore());

        Assert.NotEqual(PublicKey(first), PublicKey(second));
    }

    [Fact]
    public async Task Proof_agent_id_mismatch_exits_four_and_stores_nothing()
    {
        var store = new MemoryStore();

        var result = await Run(new FakeHandler().Reply(200, SuccessBody()), store, proof: Proof("different-agent"));

        Assert.Equal(4, result.ExitCode);
        Assert.Equal("agent_id_mismatch", result.Code);
        Assert.Equal(0, store.SaveCount);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("not json")]
    [InlineData("{\"agent_id\":\"bad id!\",\"tenant_id\":\"t\",\"agent_refresh_token\":\"r\"}")]
    [InlineData("{\"agent_id\":\"agent-0001\",\"tenant_id\":\"t\"}")]
    public async Task Invalid_success_body_exits_four_and_stores_nothing(string body)
    {
        var store = new MemoryStore();

        var result = await Run(new FakeHandler().Reply(200, body), store);

        Assert.Equal(4, result.ExitCode);
        Assert.Equal("response_invalid", result.Code);
        Assert.Equal(0, store.SaveCount);
    }

    [Theory]
    [InlineData("")]
    [InlineData("short.a.b")]
    [InlineData("has space.in.proof-value-long-enough")]
    [InlineData("only.two")]
    [InlineData("abc.def.ghi.jkl-long-enough-to-pass-length")]
    public async Task Bad_proof_exits_two_without_a_request(string proof)
    {
        var handler = new FakeHandler().Reply(200, SuccessBody());

        var result = await Run(handler, new MemoryStore(), proof: proof);

        Assert.Equal(2, result.ExitCode);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Proof_over_4096_characters_is_rejected()
    {
        var handler = new FakeHandler();

        var result = await Run(handler, new MemoryStore(), proof: "aaaa." + new string('b', 4090) + ".cc");

        Assert.Equal(2, result.ExitCode);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Bom_and_surrounding_whitespace_are_stripped_before_sending()
    {
        var handler = new FakeHandler().Reply(200, SuccessBody());

        var result = await Run(handler, new MemoryStore(), proof: "﻿ \r\n" + Proof() + "\r\n\t");

        Assert.Equal(0, result.ExitCode);
        using var doc = JsonDocument.Parse(handler.Requests.Single().Body);
        Assert.Equal(Proof(), doc.RootElement.GetProperty("enrollment_proof").GetString());
    }

    [Theory]
    [InlineData(AgentLifecycleState.Active, null, true, true)]
    [InlineData(AgentLifecycleState.Retired, "agent_revoked", false, true)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_revoked", true, true)]
    [InlineData(AgentLifecycleState.Active, null, false, false)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required", true, false)]
    [InlineData(AgentLifecycleState.Retired, "agent_deactivated", true, false)]
    public async Task Local_state_gate_refuses_with_exit_seven_before_any_request(
        AgentLifecycleState state, string? reason, bool hasCredentials, bool refused)
    {
        var handler = new FakeHandler().Reply(200, SuccessBody());
        var store = new MemoryStore();

        var result = await Run(handler, store, new AgentLifecycleSnapshot(state, reason), hasCredentials);

        if (refused)
        {
            Assert.Equal(7, result.ExitCode);
            Assert.Empty(handler.Requests);
            Assert.Equal(0, store.SaveCount);
        }
        else
        {
            Assert.Equal(0, result.ExitCode);
        }
    }

    [Fact]
    public async Task Pending_cleanup_refuses_with_exit_seven()
    {
        var handler = new FakeHandler();

        var result = await Run(handler, new MemoryStore(),
            new AgentLifecycleSnapshot(AgentLifecycleState.Retired, "agent_deactivated") { QuiescenceComplete = false });

        Assert.Equal(7, result.ExitCode);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Failed_local_save_exits_four_and_neither_logs_carry_the_proof()
    {
        var log = new CaptureLog();
        var store = new MemoryStore { FailSave = true };

        var result = await Run(new FakeHandler().Reply(200, SuccessBody()), store, log: log);

        Assert.Equal(4, result.ExitCode);
        Assert.Equal("credentials_not_saved", result.Code);
        Assert.DoesNotContain(Proof(), log.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cancellation_during_the_save_after_a_2xx_is_reported_as_a_spent_proof()
    {
        var log = new CaptureLog();
        using var cts = new CancellationTokenSource();
        var store = new MemoryStore { CancelOnSave = cts };

        var result = await Run(new FakeHandler().Reply(200, SuccessBody()), store, log: log, ct: cts.Token);

        Assert.Equal(4, result.ExitCode);
        Assert.Equal("credentials_not_saved", result.Code);
        Assert.Null(store.Saved);
        Assert.Contains("could not be saved (OperationCanceledException)", log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain(Proof(), log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("rt-secret", log.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cancellation_while_reading_a_2xx_body_is_reported_as_a_spent_proof_without_retry()
    {
        var log = new CaptureLog();
        using var cts = new CancellationTokenSource();
        var handler = new FakeHandler().ReplyCancellingBody(cts);
        var store = new MemoryStore();

        var result = await Run(handler, store, log: log, ct: cts.Token);

        Assert.Equal(4, result.ExitCode);
        Assert.Equal("response_not_read", result.Code);
        Assert.Single(handler.Requests);
        Assert.Null(store.Saved);
        Assert.Equal(0, store.SaveCount);
        Assert.Contains("OperationCanceledException", log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain(Proof(), log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("rt-secret", log.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cancellation_before_the_request_completes_still_escapes_without_a_spent_proof()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var handler = new FakeHandler();
        var store = new MemoryStore();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Run(handler, store, ct: cts.Token));

        Assert.Empty(handler.Requests);
        Assert.Null(store.Saved);
    }

    [Fact]
    public async Task Proof_refresh_token_and_private_key_never_reach_the_log_or_the_result()
    {
        var log = new CaptureLog();
        var handler = new FakeHandler().Reply(503, "").Reply(200, SuccessBody());
        var store = new MemoryStore();

        var result = await Run(handler, store, log: log, time: new ImmediateTimeProvider());

        Assert.Equal(0, result.ExitCode);
        Assert.DoesNotContain(Proof(), log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("rt-secret", log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain(Proof(), result.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("rt-secret", result.ToString(), StringComparison.Ordinal);
        Assert.Equal(Proof(), JsonDocument.Parse(handler.Requests[0].Body).RootElement.GetProperty("enrollment_proof").GetString());
    }

    // ---- helpers ----

    private static string SuccessBody(string agentId = AgentId)
        => $"{{\"agent_id\":\"{agentId}\",\"tenant_id\":\"tenant-1\",\"agent_refresh_token\":\"rt-secret\",\"tenant_name\":\"Acme\"}}";

    internal static string Proof(string? agentId = AgentId)
    {
        static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payload = agentId is null ? "{\"sub\":\"x\"}" : $"{{\"agent_id\":\"{agentId}\",\"sub\":\"x\"}}";
        return B64("{\"alg\":\"HS256\"}") + "." + B64(payload) + ".c2lnbmF0dXJl";
    }

    private static string PublicKey(FakeHandler handler)
    {
        using var doc = JsonDocument.Parse(handler.Requests.Single().Body);
        return doc.RootElement.GetProperty("agent_public_key_pem").GetString()!;
    }

    internal static HeadlessEnrollmentOptions Options() => new("https://backend.example/", "dev-fp-1", "1.2.3", "build-1", "dev", "HOST");

    private static Task<HeadlessEnrollmentResult> Run(
        FakeHandler handler, MemoryStore store, AgentLifecycleSnapshot? state = null, bool hasCredentials = false,
        string? proof = null, CaptureLog? log = null, TimeProvider? time = null, CancellationToken ct = default)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.example") };
        return new HeadlessEnrollment(http, log: log, time: time ?? new ImmediateTimeProvider())
            .RunAsync(proof ?? Proof(), Options(), state ?? new AgentLifecycleSnapshot(), hasCredentials, store, ct);
    }

    internal sealed record CapturedRequest(string Path, string Body, string? Authorization);

    internal sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Queue<Func<HttpResponseMessage>> _script = new();
        public List<CapturedRequest> Requests { get; } = [];

        public FakeHandler Reply(int status, string body, TimeSpan? retryAfter = null)
        {
            _script.Enqueue(() =>
            {
                var response = new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
                if (retryAfter is { } delay)
                    response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(delay);
                return response;
            });
            return this;
        }

        /// <summary>A 200 whose body read cancels <paramref name="cts"/> and then observes the cancellation.</summary>
        public FakeHandler ReplyCancellingBody(CancellationTokenSource cts)
        {
            _script.Enqueue(() => new HttpResponseMessage(HttpStatusCode.OK) { Content = new CancellingBodyContent(cts) });
            return this;
        }

        public FakeHandler Throw(Exception ex)
        {
            _script.Enqueue(() => throw ex);
            return this;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new(request.RequestUri!.AbsolutePath, request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken),
                request.Headers.Authorization?.ToString()));
            if (_script.Count == 0)
                throw new InvalidOperationException("Unexpected extra request.");
            return _script.Dequeue()();
        }
    }

    /// <summary>Completes every timer at once and records the requested delays.</summary>
    internal sealed class ImmediateTimeProvider : TimeProvider
    {
        public List<TimeSpan> Delays { get; } = [];
        public override DateTimeOffset GetUtcNow() => new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            Delays.Add(dueTime);
            ThreadPool.QueueUserWorkItem(_ => callback(state));
            return new NoopTimer();
        }

        private sealed class NoopTimer : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period) => false;
            public void Dispose() { }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    internal sealed class CaptureLog : IAgentLogger
    {
        private readonly StringBuilder _text = new();
        public string Text { get { lock (_text) return _text.ToString(); } }
        private void Add(string m) { lock (_text) _text.AppendLine(m); }
        public void Info(string message) => Add(message);
        public void Warn(string message) => Add(message);
        public void Error(string message, Exception? ex = null) => Add(message + ex);
    }

    internal sealed class MemoryStore : ISecretStore
    {
        public (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)? Saved { get; set; }
        public int SaveCount { get; private set; }
        public bool FailSave { get; init; }
        public CancellationTokenSource? CancelOnSave { get; init; }

        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
        {
            if (FailSave)
                throw new IOException("disk full");
            if (CancelOnSave is { } cts)
            {
                cts.Cancel();
                ct.ThrowIfCancellationRequested();
            }
            SaveCount++;
            Saved = (identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey);
            return Task.CompletedTask;
        }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Saved is { } s ? Task.FromResult(s) : throw new FileNotFoundException();

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
