using System.Net;
using System.Text;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

// Support/unit evidence: the HTTP and updater boundaries here are deliberately
// controlled; these tests do not certify the installed SYSTEM service or MSI.
public sealed class AgentLifecycleControlTests
{
    [Theory]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(409)]
    [InlineData(500)]
    public async Task WrongStatusCannotRetireOrClearCredentials(int status)
    {
        using var http = new HttpClient();
        using var response = JsonResponse((HttpStatusCode)status,
            """{"error_code":"AUTH_UNAUTHORIZED","detail":{"code":"agent_revoked"}}""");
        var error = await AgentHttpFailure.CreateAsync("Heartbeat", response, http, default);
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new SecretStore();
        await new AgentLifecycleController(state, secrets, quiesce: _ => Task.CompletedTask)
            .RecordHttpFailureAsync(Info(error), false, false, default, authenticatedControlPlane: true);
        Assert.NotEqual(AgentLifecycleState.Retired, (await state.LoadAsync(default)).State);
        Assert.Equal("original", secrets.RefreshToken);
        Assert.False(secrets.Cleared);
    }

    [Fact]
    public async Task CanonicalTerminalRequiresExpectedAuthenticatedOperation()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new SecretStore();
        await new AgentLifecycleController(state, secrets, quiesce: _ => Task.CompletedTask)
            .RecordHttpFailureAsync(Terminal(), false, false, default);
        Assert.Equal(AgentLifecycleState.AuthSuspect, (await state.LoadAsync(default)).State);
        Assert.False(secrets.Cleared);
    }

    [Fact]
    public async Task TerminalIntentIsDurableBeforeCleanupAndCredentialsClear()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new SecretStore();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var controller = new AgentLifecycleController(state, secrets, quiesce: async _ =>
        {
            entered.SetResult();
            await release.Task;
        });
        var retiring = controller.RecordHttpFailureAsync(Terminal(), false, false, default, authenticatedControlPlane: true);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var pending = await state.LoadAsync(default);
        Assert.Equal(AgentLifecycleState.Retired, pending.State);
        Assert.False(pending.QuiescenceComplete);
        Assert.False(secrets.Cleared);
        await Assert.ThrowsAsync<AgentRetiredException>(() => controller.EnsureAutomaticNetworkAllowedAsync(default));
        release.SetResult();
        await Assert.ThrowsAsync<AgentRetiredException>(() => retiring);
        Assert.True(secrets.Cleared);
        Assert.True((await state.LoadAsync(default)).QuiescenceComplete);
    }

    [Fact]
    public async Task MissingCleanupRemainsPendingAndRestartCompletesLocally()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new SecretStore();
        await Assert.ThrowsAsync<AgentRetiredException>(() =>
            new AgentLifecycleController(state, secrets).RecordHttpFailureAsync(Terminal(), false, false, default, authenticatedControlPlane: true));
        Assert.False((await state.LoadAsync(default)).QuiescenceComplete);
        Assert.False(secrets.Cleared);
        var recovered = await new AgentLifecycleController(state, secrets, quiesce: _ => Task.CompletedTask)
            .CompletePendingQuiescenceAsync(default);
        Assert.Equal(AgentLifecycleState.Retired, recovered.State);
        Assert.True(recovered.QuiescenceComplete);
        Assert.True(secrets.Cleared);
    }

    [Fact]
    public async Task OnlySecondManualGenericRejectionRequiresReenrollment()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new SecretStore();
        var controller = new AgentLifecycleController(state, secrets, quiesce: _ => Task.CompletedTask);
        var failure = new AgentHttpFailureInfo(HttpStatusCode.Unauthorized, null, null, null, null, null);
        await controller.RecordHttpFailureAsync(failure, true, false, default);
        Assert.Equal(0, (await state.LoadAsync(default)).GenericAuthFailureCount);
        await controller.RecordHttpFailureAsync(failure, true, true, default);
        var first = await state.LoadAsync(default);
        Assert.Equal(AgentLifecycleState.AuthSuspect, first.State);
        Assert.Equal(1, first.GenericAuthFailureCount);
        await controller.RecordHttpFailureAsync(failure, true, true, default);
        var second = await state.LoadAsync(default);
        Assert.Equal(AgentLifecycleState.NeedsReenrollment, second.State);
        Assert.Equal(2, second.GenericAuthFailureCount);
        Assert.False(secrets.Cleared);
    }

    [Fact]
    public async Task ReenrollCodeNeverClearsIdentity()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new SecretStore();
        await new AgentLifecycleController(state, secrets, quiesce: _ => Task.CompletedTask)
            .RecordHttpFailureAsync(Terminal() with { DetailCode = "agent_reenroll_required" }, true, false, default, authenticatedControlPlane: true);
        Assert.Equal(AgentLifecycleState.NeedsReenrollment, (await state.LoadAsync(default)).State);
        Assert.False(secrets.Cleared);
        Assert.Equal("original", secrets.RefreshToken);
    }

    [Fact]
    public async Task RoutineHeartbeatAndRetryKeepUpdateAuthorizationEpoch()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var original = await state.LoadAsync(default);
        var controller = new AgentLifecycleController(state);
        await controller.RecordTransientFailureAsync("network_transient", null, default);
        await controller.SetNextAttemptAsync(DateTimeOffset.UtcNow.AddMinutes(2), default);
        await controller.MarkActiveAsync(default, original.Generation);
        var after = await state.LoadAsync(default);
        Assert.Equal(original.Generation, after.Generation);
        Assert.True(after.Revision > original.Revision);
        Assert.Equal(AgentLifecycleState.Active, after.State);
    }

    [Fact]
    public async Task StaleSuccessCannotReviveRetiredOrOverwriteNewEnrollment()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var original = await state.LoadAsync(default);
        var controller = new AgentLifecycleController(state, quiesce: _ => Task.CompletedTask);
        await Assert.ThrowsAsync<AgentRetiredException>(() => controller.RecordHttpFailureAsync(
            Terminal() with { DetailCode = "agent_deactivated" }, false, false, default, authenticatedControlPlane: true));
        await Assert.ThrowsAsync<AgentLifecycleDormantException>(() => controller.MarkActiveAsync(default, original.Generation));
        var denied = await state.LoadAsync(default);
        var nonce = Guid.NewGuid().ToString("N");
        var adopted = await controller.CompleteEnrollmentAsync(denied.Generation, nonce, default);
        Assert.True(adopted.Generation > denied.Generation);
        Assert.Equal(nonce, adopted.LastEnrollmentNonce);
        await controller.RecordHttpFailureAsync(Terminal(), false, false, default,
            expectedGeneration: original.Generation, authenticatedControlPlane: true);
        Assert.Equal(adopted, await state.LoadAsync(default));
        await Assert.ThrowsAsync<AgentLifecycleDormantException>(() => controller.CompleteEnrollmentAsync(adopted.Generation, nonce, default));
    }

    [Fact]
    public async Task MalformedBodyPreservesSingleRetryAfterAndRequestId()
    {
        using var http = new HttpClient();
        using var response = JsonResponse(HttpStatusCode.TooManyRequests, "{broken");
        response.Headers.TryAddWithoutValidation("Retry-After", "120");
        response.Headers.TryAddWithoutValidation("X-Request-ID", "req-123");
        var error = Assert.IsType<AgentHttpException>(await AgentHttpFailure.CreateAsync("Heartbeat", response, http, default));
        Assert.Equal(TimeSpan.FromSeconds(120), error.RetryAfter);
        Assert.Equal("req-123", error.RequestId);
        Assert.Null(error.Code);
        Assert.DoesNotContain("broken", error.Message);
    }

    [Theory]
    [InlineData("{\"error_code\":\"AUTH_UNAUTHORIZED\",\"detail\":{\"code\":\"agent_revoked\",\"code\":\"agent_revoked\"}}")]
    [InlineData("{\"detail\":{\"code\":\"agent_revoked\"}}")]
    [InlineData("{\"error_code\":\"agent_revoked\"}")]
    public async Task NoncanonicalTerminalEnvelopeDoesNotCarryTerminalAuthority(string json)
    {
        using var http = new HttpClient();
        using var response = JsonResponse(HttpStatusCode.Unauthorized, json);
        var error = await AgentHttpFailure.CreateAsync("Heartbeat", response, http, default);
        Assert.False(AgentLifecycleStatePolicy.IsTerminalCode((error as AgentHttpException)?.Code));
    }

    [Fact]
    public async Task DurableCasRejectsLostUpdateAndPersistsRetryAcrossInstances()
    {
        var directory = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(directory, "lifecycle.json");
        try
        {
            var first = new DurableAgentLifecycleStateStore(path);
            var second = new DurableAgentLifecycleStateStore(path);
            var initial = await first.LoadAsync(default);
            var next = initial with { State = AgentLifecycleState.Degraded, TransientFailureCount = 7, NextAttemptUtc = DateTimeOffset.UtcNow.AddMinutes(3) };
            Assert.NotNull(await first.TrySaveAsync(next, initial.Revision, default));
            Assert.Null(await second.TrySaveAsync(initial, initial.Revision, default));
            var persisted = await new DurableAgentLifecycleStateStore(path).LoadAsync(default);
            Assert.Equal(7, persisted.TransientFailureCount);
            Assert.Equal(next.NextAttemptUtc, persisted.NextAttemptUtc);
            Assert.Equal(initial.Generation, persisted.Generation);
            Assert.Equal(initial.Revision + 1, persisted.Revision);
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData("status", false, true)]
    [InlineData("check", false, true)]
    [InlineData("retry", false, false)]
    [InlineData("enrollment-adopt", false, false)]
    [InlineData("unregister", false, false)]
    [InlineData("retry", true, true)]
    [InlineData("unregister", true, true)]
    [InlineData("https://untrusted.invalid/file.msi", true, false)]
    public void PipeOperationAuthorityIsExplicit(string operation, bool privileged, bool allowed)
        => Assert.Equal(allowed, AgentLocalControlProtocol.IsAllowed(new(operation), privileged));

    [Fact]
    public async Task PipeRejectsUnknownFieldsAndUnboundApply()
    {
        Assert.False(AgentLocalControlProtocol.IsAllowed(new("apply"), true));
        Assert.False(AgentLocalControlProtocol.IsAllowed(new("apply", "../installer.exe"), true));
        Assert.True(AgentLocalControlProtocol.IsAllowed(new("apply", Guid.NewGuid().ToString("N")), false));
        using var stream = new MemoryStream();
        await AgentLocalControlProtocol.WriteAsync(stream, new { operation = "check", schemaVersion = AgentLocalControlProtocol.SchemaVersion, url = "https://untrusted.invalid" }, default);
        stream.Position = 0;
        await Assert.ThrowsAsync<System.Text.Json.JsonException>(() => AgentLocalControlProtocol.ReadAsync<AgentLocalControlRequest>(stream, default));
        Assert.Equal(0, (int)(AgentLocalControlPipe.ClientRights & System.IO.Pipes.PipeAccessRights.CreateNewInstance));
    }

    private static AgentHttpFailureInfo Terminal() => new(HttpStatusCode.Unauthorized, "AUTH_UNAUTHORIZED", "agent_revoked", null, null, null);
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InFlightRefreshCannotPublishOrBlockNewEnrollment(bool malformed)
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new SecretStore();
        var arrived = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(new CallbackHandler(async () =>
        {
            arrived.SetResult();
            await release.Task;
            return JsonResponse(HttpStatusCode.OK, malformed ? "{}" :
                """{"access_token":"access","expires_in":3600,"refresh_token":"rotated"}""");
        })) { BaseAddress = new Uri("https://backend.invalid") };
        var manager = new AgentTokenManager(http, secrets, lifecycleState: state);
        var refreshing = manager.GetAccessTokenAsync(default);
        await arrived.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var before = await state.LoadAsync(default);
        var adopted = await new AgentLifecycleController(state).CompleteEnrollmentAsync(before.Generation, Guid.NewGuid().ToString("N"), default);
        release.SetResult();
        await Assert.ThrowsAnyAsync<Exception>(() => refreshing);
        Assert.Equal("original", secrets.RefreshToken);
        Assert.Equal(adopted, await state.LoadAsync(default));
    }

    [Fact]
    public async Task CancelledDpapiPublicationPreservesPreviousEncryptedRegistration()
    {
        var directory = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new DpapiSecretStore(SecretStoreScope.User, directory);
            await store.SaveAsync(new("agent", "tenant"), "original", "test-key", "https://backend.invalid", null, null, default);
            var original = await File.ReadAllBytesAsync(Path.Combine(directory, "secrets.json"));
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.SaveAsync(new("other", "tenant"), "replacement", "test-key", "https://backend.invalid", null, null, cancelled.Token));
            Assert.Equal(original, await File.ReadAllBytesAsync(Path.Combine(directory, "secrets.json")));
            Assert.Equal("original", (await store.LoadAsync(default)).RefreshToken);
            Assert.Empty(Directory.GetFiles(directory, "*.tmp"));
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, true); }
    }

    private sealed class CallbackHandler(Func<Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => callback();
    }
    private static AgentHttpFailureInfo Info(HttpRequestException error) => error is AgentHttpException typed ? typed.Failure : new(error.StatusCode!.Value, null, null, null, null, null);
    private static HttpResponseMessage JsonResponse(HttpStatusCode status, string json) => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private sealed class SecretStore : ISecretStore
    {
        public string RefreshToken { get; private set; } = "original";
        public bool Cleared { get; private set; }
        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((new AgentIdentity("agent", "tenant"), RefreshToken, "key", "https://backend.invalid", (string?)null, (string?)null));
        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
        { RefreshToken = refreshToken; return Task.CompletedTask; }
        public Task ClearAsync(CancellationToken ct) { Cleared = true; RefreshToken = ""; return Task.CompletedTask; }
    }
}
