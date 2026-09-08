using System.Net;
using System.IO.Pipes;
using System.Security.Principal;
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

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Conflict)]
    public async Task ResourceOperationStatusDoesNotBlockOrQuiesce(HttpStatusCode status)
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var quiesceCalls = 0;
        var controller = new AgentLifecycleController(state, quiesce: _ =>
        {
            quiesceCalls++;
            return Task.CompletedTask;
        });

        var result = await controller.RecordHttpFailureAsync(
            new AgentHttpFailureInfo(status, null, null, null, null, null),
            duringRefresh: false,
            manualOperation: false,
            default,
            resourceOperation: true);

        Assert.Equal(AgentLifecycleState.Active, result.State);
        Assert.Equal(AgentLifecycleState.Active, (await state.LoadAsync(default)).State);
        Assert.Equal(0, quiesceCalls);
    }

    [Fact]
    public async Task ResourceOperationWithExplicitConfigCodeStillBlocksAndQuiesces()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var quiesceCalls = 0;
        var controller = new AgentLifecycleController(state, quiesce: _ =>
        {
            quiesceCalls++;
            return Task.CompletedTask;
        });

        var result = await controller.RecordHttpFailureAsync(
            new AgentHttpFailureInfo(HttpStatusCode.NotFound, null, "agent_config_mismatch", null, null, null),
            duringRefresh: false,
            manualOperation: false,
            default,
            resourceOperation: true);

        Assert.Equal(AgentLifecycleState.BlockedConfig, result.State);
        Assert.Equal(AgentLifecycleState.BlockedConfig, (await state.LoadAsync(default)).State);
        Assert.Equal(1, quiesceCalls);
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

    [Theory]
    [InlineData(TokenImpersonationLevel.None, true)]
    [InlineData(TokenImpersonationLevel.Anonymous, false)]
    public async Task PipeAuthenticatesTheReadRequestBeforeDispatch(TokenImpersonationLevel impersonation, bool allowed)
    {
        // Real local Windows pipe evidence; this does not replace installed SYSTEM/SCM acceptance.
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var name = "cerberus-control-test-" + Guid.NewGuid().ToString("N");
        await using var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, impersonation);
        var accepted = pipe.WaitForConnectionAsync(timeout.Token);
        await client.ConnectAsync(timeout.Token);
        await accepted;
        var expected = new AgentLocalControlResponse(true, "health_response", CurrentVersion: "1.2.3");
        var dispatched = false;
        var server = new AgentLocalControlServer((request, _) =>
        {
            Assert.Equal("status", request.Operation);
            dispatched = true;
            return Task.FromResult(expected);
        });
        // Start the real server handler before any client bytes exist: this is the MSI connection ordering.
        var handling = server.HandleConnectionAsync(pipe, timeout.Token);
        if (allowed)
        {
            await AgentLocalControlProtocol.WriteAsync(client, new AgentLocalControlRequest("status"), timeout.Token);
            var response = await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(client, timeout.Token);
            Assert.Equal(expected, response);
        }
        else
        {
            await Assert.ThrowsAnyAsync<IOException>(async () =>
            {
                await AgentLocalControlProtocol.WriteAsync(client, new AgentLocalControlRequest("status"), timeout.Token);
                await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(client, timeout.Token);
            });
        }
        await handling;
        Assert.Equal(allowed, dispatched);
        if (!allowed)
        {
            // A rejected identity must not fault this server's next connection.
            await using var nextPipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
            await using var nextClient = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            var nextAccepted = nextPipe.WaitForConnectionAsync(timeout.Token);
            await nextClient.ConnectAsync(timeout.Token);
            await nextAccepted;
            var nextHandling = server.HandleConnectionAsync(nextPipe, timeout.Token);
            await AgentLocalControlProtocol.WriteAsync(nextClient, new AgentLocalControlRequest("status"), timeout.Token);
            Assert.Equal(expected, await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(nextClient, timeout.Token));
            await nextHandling;
            Assert.True(dispatched);
        }
    }

    [Fact]
    public async Task PipeConnectionWithoutAFrameCancelsWithoutDispatch()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var stopped = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
        var name = "cerberus-control-test-" + Guid.NewGuid().ToString("N");
        await using var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accepted = pipe.WaitForConnectionAsync(timeout.Token);
        await client.ConnectAsync(timeout.Token);
        await accepted;
        var dispatched = false;
        var server = new AgentLocalControlServer((_, _) =>
        {
            dispatched = true;
            return Task.FromResult(new AgentLocalControlResponse(true, "unexpected"));
        });
        var handling = server.HandleConnectionAsync(pipe, stopped.Token);
        stopped.Cancel();
        await handling.WaitAsync(timeout.Token);
        Assert.False(dispatched);
        await Assert.ThrowsAnyAsync<IOException>(() =>
            AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(client, timeout.Token));
    }

    [Theory]
    [InlineData("zero-length")]
    [InlineData("negative-length")]
    [InlineData("oversized-length")]
    [InlineData("nonobject")]
    [InlineData("null")]
    [InlineData("duplicate-field")]
    [InlineData("malformed-json")]
    [InlineData("unknown-field")]
    [InlineData("wrong-field-type")]
    [InlineData("excessive-depth")]
    [InlineData("truncated-header")]
    [InlineData("truncated-body")]
    [InlineData("anonymous")]
    [InlineData("cancelled")]
    public async Task PipeRepeatedRejectedConnectionsCompleteWithoutDispatchAndNextRequestSucceeds(string rejectedInput)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var name = "cerberus-control-test-" + Guid.NewGuid().ToString("N");
        var dispatched = 0;
        var expected = new AgentLocalControlResponse(true, "healthy");
        var server = new AgentLocalControlServer((_, _) =>
        {
            dispatched++;
            return Task.FromResult(expected);
        });
        var valid = Frame("{\"operation\":\"status\"}");
        var rejected = rejectedInput switch
        {
            "zero-length" => BitConverter.GetBytes(0),
            "negative-length" => BitConverter.GetBytes(-1),
            "oversized-length" => BitConverter.GetBytes(AgentLocalControlProtocol.MaxFrameBytes + 1),
            "nonobject" => Frame("[]"),
            "null" => Frame("null"),
            "duplicate-field" => Frame("{\"operation\":\"status\",\"operation\":\"status\"}"),
            "malformed-json" => Frame("{broken"),
            "unknown-field" => Frame("{\"operation\":\"status\",\"unknown\":true}"),
            "wrong-field-type" => Frame("{\"operation\":1}"),
            "excessive-depth" => Frame("{\"operation\":[[[[[]]]]]}"),
            "truncated-header" => new byte[] { 1, 0 },
            "truncated-body" => valid[..^1],
            "anonymous" or "cancelled" => valid,
            _ => throw new ArgumentOutOfRangeException(nameof(rejectedInput))
        };

        // Four faulted tasks previously exhausted RunAsync's active-connection budget.
        var rejectedTasks = new List<Task>();
        for (var attempt = 0; attempt < 4; attempt++)
        {
            using var stopped = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
            await using var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
            await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous,
                rejectedInput == "anonymous" ? TokenImpersonationLevel.Anonymous : TokenImpersonationLevel.None);
            var accepted = pipe.WaitForConnectionAsync(timeout.Token);
            await client.ConnectAsync(timeout.Token);
            await accepted;
            var handling = server.HandleConnectionAsync(pipe, stopped.Token);
            rejectedTasks.Add(handling);
            if (rejectedInput == "cancelled")
                stopped.Cancel();
            else
                await client.WriteAsync(rejected, timeout.Token);
            if (rejectedInput.StartsWith("truncated-", StringComparison.Ordinal))
                await client.DisposeAsync();
            else
                Assert.Equal(0, await client.ReadAsync(new byte[1], timeout.Token));
            await handling.WaitAsync(timeout.Token);
            Assert.True(handling.IsCompletedSuccessfully);
            Assert.Equal(0, dispatched);
        }
        // Exercise the listener's completed-task await boundary, not just client disconnects.
        await await Task.WhenAny(rejectedTasks);
        await Task.WhenAll(rejectedTasks);

        await using var nextPipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
        await using var nextClient = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var nextAccepted = nextPipe.WaitForConnectionAsync(timeout.Token);
        await nextClient.ConnectAsync(timeout.Token);
        await nextAccepted;
        var nextHandling = server.HandleConnectionAsync(nextPipe, timeout.Token);
        await nextClient.WriteAsync(valid, timeout.Token);
        Assert.Equal(expected, await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(nextClient, timeout.Token));
        await nextHandling.WaitAsync(timeout.Token);
        Assert.Equal(1, dispatched);

        static byte[] Frame(string json)
        {
            var payload = Encoding.UTF8.GetBytes(json);
            return [.. BitConverter.GetBytes(payload.Length), .. payload];
        }
    }

    [Fact]
    public async Task PipeDoesNotTreatAuthorizedHandlerFailureAsMalformedInput()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var name = "cerberus-control-test-" + Guid.NewGuid().ToString("N");
        await using var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var accepted = pipe.WaitForConnectionAsync(timeout.Token);
        await client.ConnectAsync(timeout.Token);
        await accepted;
        var failure = new InvalidDataException("Trusted handler failure must remain observable.");
        var server = new AgentLocalControlServer((_, _) => Task.FromException<AgentLocalControlResponse>(failure));
        var handling = server.HandleConnectionAsync(pipe, timeout.Token);
        await AgentLocalControlProtocol.WriteAsync(client, new AgentLocalControlRequest("status"), timeout.Token);
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidDataException>(() => handling.WaitAsync(timeout.Token)));
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
