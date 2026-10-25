using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Unit/support evidence for the signed agent_state store and handler (contract v1 (b)). The queue wiring
// that calls OnResultFinalAsync is covered by the envelope queue tests; ServiceMode wiring is not covered here.
public sealed class AgentSignedStateTests : IDisposable
{
    private const string Revoked = "agent_revoked";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
    private string StatePath => Path.Combine(_dir, AgentSignedStateStore.FileName);

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
                Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup of the per-test temp directory.
        }
    }

    private static string P(long seq, string rest = "") => $"{{\"state_seq\":{seq}{rest}}}";

    private static string Revoke(string reason) => $",\"revoke\":{{\"reason_code\":\"{reason}\"}}";

    [Fact]
    public async Task StaleSeq_FailsAndChangesNothing()
    {
        var f = new Fixture(StatePath);
        Assert.Equal("DONE", (await f.Handle("c1", """{"state_seq":5,"quarantine":{"active":true}}""")).Status);

        foreach (var seq in new[] { 5, 3 })
        {
            var result = await f.Handle($"c-{seq}", P(seq, ""","quarantine":{"active":false}"""));
            Assert.Equal("FAILED", result.Status);
            Assert.Equal("stale_state_seq", result.Stderr);
        }

        Assert.True(f.Store.IsQuarantined());
        Assert.Equal(5, f.Store.Load("agent-a").StateSeq);
        Assert.Equal("DONE", (await f.Handle("c6", """{"state_seq":6,"quarantine":{"active":false}}""")).Status);
        Assert.False(f.Store.IsQuarantined());
    }

    [Fact]
    public async Task Quarantine_IsDurableGatesImmediatelyAndClears()
    {
        var f = new Fixture(StatePath);
        Assert.False(f.Store.IsQuarantined());

        var result = await f.Handle("c1", """{"state_seq":1,"quarantine":{"active":true}}""");

        Assert.True(f.Store.IsQuarantined());
        Assert.True(new AgentSignedStateStore(StatePath).IsQuarantined("agent-a"));
        Assert.Equal(0, f.Cancels);

        await f.Handle("c2", """{"state_seq":2,"quarantine":{"active":false}}""");
        Assert.False(f.Store.IsQuarantined());
        Assert.False(new AgentSignedStateStore(StatePath).IsQuarantined("agent-a"));
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public async Task Result_NamesTheAppliedKeysInFixedOrder()
    {
        var f = new Fixture(StatePath);

        var result = await f.Handle("c1",
            """{"revoke":{"reason_code":"agent_revoked"},"quarantine":{"active":true},"registration_state":"claimed","state_seq":4}""");

        using var body = JsonDocument.Parse(CommandEnvelope.BuildResultBody(result.Status, result.ExitCode, result.Stderr, result.PostVerify, new string('a', 64)));
        var verify = body.RootElement.GetProperty("post_verify");
        Assert.Equal("agent.state_result.v1", verify.GetProperty("schema").GetString());
        Assert.Equal(4, verify.GetProperty("state_seq").GetInt64());
        Assert.Equal(new[] { "registration_state", "quarantine", "revoke" },
            verify.GetProperty("applied").EnumerateArray().Select(e => e.GetString()).ToArray());
        Assert.Equal("claimed", f.Store.Load("agent-a").RegistrationState);
    }

    [Theory]
    [InlineData("agent_revoked")]
    [InlineData("agent_deactivated")]
    public async Task Revoke_RetiresOnlyAfterTheResultIsFinalThenCancelsTheQueue(string reason)
    {
        var f = new Fixture(StatePath);
        var result = await f.Handle("c1", P(1, Revoke(reason)));

        Assert.Equal("DONE", result.Status);
        Assert.True(f.Store.IsQuarantined());
        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.False(f.Secrets.Cleared);
        Assert.Equal(0, f.Cancels);

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        var snapshot = await f.Lifecycle.LoadAsync(default);
        Assert.Equal(AgentLifecycleState.Retired, snapshot.State);
        Assert.Equal(reason, snapshot.ReasonCode);
        Assert.True(f.Secrets.Cleared);
        Assert.Equal(1, f.Quiesces);
        Assert.Equal(1, f.Cancels);
    }

    [Fact]
    public async Task OnResultFinal_IgnoresUnknownAndRepeatedIds()
    {
        var f = new Fixture(StatePath);
        await f.Handle("c1", P(1, Revoke(Revoked)));

        await f.Handler.OnResultFinalAsync("agent-a", "never-seen", default);
        await f.Handler.OnResultFinalAsync("agent-b", "c1", default);
        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Equal(0, f.Cancels);

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);
        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);
        Assert.Equal(1, f.Cancels);
        Assert.Equal(1, f.Quiesces);
    }

    [Fact]
    public async Task OnResultFinal_CancelsEvenWhenTheLifecycleWriteFails()
    {
        var f = new Fixture(StatePath, failQuiesce: true);
        await f.Handle("c1", P(1, Revoke(Revoked)));

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Equal(1, f.Cancels);
    }

    [Fact]
    public async Task OnResultFinal_ForARevokeIssuedToAnOlderRegistration_DoesNotRetireTheCurrentOne()
    {
        var f = new Fixture(StatePath);
        await f.Handle("c1", P(1, Revoke(Revoked)));
        f.AgentId = "agent-b";

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.False(f.Secrets.Cleared);
        Assert.Equal(0, f.Quiesces);
        Assert.Equal(0, f.Cancels);
        Assert.Null(f.Store.Load("agent-a").PendingRevoke);
        Assert.False(f.Store.IsQuarantined("agent-a"));
    }

    [Fact]
    public async Task OnResultFinal_WhenTheCredentialIdIsUnavailable_StillRecordsTheRevoke()
    {
        var f = new Fixture(StatePath);
        await f.Handle("c1", P(1, Revoke(Revoked)));
        f.AgentIdUnavailable = true;

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Equal(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Equal(1, f.Cancels);
        Assert.Null(f.Store.Load("agent-a").PendingRevoke);
    }

    [Fact]
    public async Task Recovery_ForARevokeIssuedToAnOlderRegistration_DoesNotRetireTheCurrentOne()
    {
        var f = new Fixture(StatePath);
        await f.Handle("c1", P(1, Revoke(Revoked)));
        f.AgentId = "agent-b";
        var replay = new CommandReplayStore(Path.Combine(_dir, CommandReplayStore.FileName), TimeProvider.System);
        Assert.True(replay.IsAvailable);

        await f.Handler.RecoverPendingRevokeAsync(replay, default);

        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Equal(0, f.Cancels);
        Assert.Equal(0, f.Quiesces);
        Assert.False(f.Store.IsQuarantined());
    }

    [Fact]
    public async Task InvalidPayload_IsRefusedByTheHandler()
    {
        var f = new Fixture(StatePath);

        await Assert.ThrowsAsync<InvalidDataException>(() => f.Handle("c1", """{"state_seq":1,"surprise":true}"""));
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Handle("c2", """{"state_seq":2}"""));

        Assert.Equal(0, f.Store.Load("agent-a").StateSeq);
    }

    [Fact]
    public async Task UnknownKeyInASignedAgentState_IsRejectedAsPayloadInvalidBeforeTheHandler()
    {
        await using var h = EnvelopeHarness.Create();

        await h.Process(h.Cmd(p =>
        {
            p.Type = "agent_state";
            p.PayloadJson = """{"state_seq":1,"quarantine":{"active":true},"surprise":1}""";
        }));

        Assert.Equal(1, h.Rejections("payload_invalid"));
        Assert.Equal(0, h.State.Calls);
    }

    [Fact]
    public async Task Rebind_NewAgentIdStartsAtSeq1WithoutQuarantineAndReplacesTheRecord()
    {
        var f = new Fixture(StatePath);
        for (var seq = 1; seq <= 5; seq++)
            await f.Handle($"a{seq}", P(seq, ""","quarantine":{"active":true}"""));
        Assert.True(f.Store.IsQuarantined());
        Assert.Equal(5, f.Store.Load("agent-a").StateSeq);

        f.AgentId = "agent-b";
        await f.Track(default);

        Assert.False(f.Store.IsQuarantined());
        Assert.Equal(0, f.Store.Load("agent-b").StateSeq);
        Assert.Equal("DONE", (await f.Handle("b1", """{"state_seq":1,"registration_state":"claimed"}""")).Status);

        Assert.False(f.Store.IsQuarantined());
        Assert.Equal(1, f.Store.Load("agent-b").StateSeq);
        Assert.Equal(0, f.Store.Load("agent-a").StateSeq);
        Assert.False(f.Store.Load("agent-a").QuarantineActive);
        Assert.False(new AgentSignedStateStore(StatePath).IsQuarantined("agent-a"));
    }

    [Fact]
    public void Rebind_RecordWrittenForAIsIgnoredWhenTheLoadedCredentialIsB()
    {
        var writer = new AgentSignedStateStore(StatePath);
        Assert.True(writer.TrySave(new AgentSignedState("agent-a", 5, true, "claimed")));

        var reader = new AgentSignedStateStore(StatePath);
        Assert.Equal(AgentSignedState.Empty("agent-b"), reader.Load("agent-b"));
        Assert.False(reader.IsQuarantined("agent-b"));
        Assert.True(reader.IsQuarantined("agent-a"));
        Assert.Equal(5, reader.Load("agent-a").StateSeq);
    }

    [Fact]
    public async Task RevokePending_DoesNotCarryOverToAnotherAgentId()
    {
        var f = new Fixture(StatePath);
        await f.Handle("c1", P(1, Revoke(Revoked)));
        Assert.True(f.Store.IsQuarantined());

        f.AgentId = "agent-b";
        await f.Track(default);

        Assert.False(f.Store.IsQuarantined());
    }

    [Fact]
    public void CorruptFile_FailsClosedUntilTheNextSignedWrite()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(StatePath, "{not json");
        var store = new AgentSignedStateStore(StatePath);

        Assert.True(store.IsQuarantined());
        Assert.True(store.IsQuarantined("agent-a"));
        Assert.Equal(0, store.Load("agent-a").StateSeq);
        Assert.Contains("\"reset\":\"unreadable\"", File.ReadAllText(StatePath));
        Assert.Single(Directory.GetFiles(_dir, AgentSignedStateStore.FileName + ".corrupt-*"));

        Assert.True(store.TrySave(new AgentSignedState("agent-a", 1, false, null)));
        Assert.False(store.IsQuarantined("agent-a"));
        Assert.False(new AgentSignedStateStore(StatePath).IsQuarantined("agent-a"));
        Assert.DoesNotContain("reset", File.ReadAllText(StatePath));
    }

    [Fact]
    public void CorruptFile_QuarantineSurvivesARestartForAnyAgentId()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(StatePath, "{not json");
        Assert.True(new AgentSignedStateStore(StatePath).IsQuarantined("agent-a"));

        var restarted = new AgentSignedStateStore(StatePath);

        Assert.True(restarted.IsQuarantined("agent-a"));
        Assert.True(restarted.IsQuarantined("agent-b"));
        Assert.True(restarted.IsQuarantined());
        Assert.Equal(0, restarted.Load("agent-a").StateSeq);
        Assert.Single(Directory.GetFiles(_dir, AgentSignedStateStore.FileName + ".corrupt-*"));
    }

    [Fact]
    public async Task CorruptFile_ASignedStateWriteClearsTheResetAcrossRestarts()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(StatePath, "{not json");
        var f = new Fixture(StatePath);
        await f.Track(default);
        Assert.True(f.Store.IsQuarantined());

        Assert.Equal("DONE", (await f.Handle("c1", P(1, ""","quarantine":{"active":false}"""))).Status);

        Assert.False(f.Store.IsQuarantined());
        var restarted = new AgentSignedStateStore(StatePath);
        Assert.False(restarted.IsQuarantined("agent-a"));
        Assert.Equal(1, restarted.Load("agent-a").StateSeq);
        Assert.DoesNotContain("reset", File.ReadAllText(StatePath));
    }

    // Corrupt file loaded after the agent id is tracked: the persisted marker carries the real id. Returns a restarted fixture.
    private async Task<Fixture> RestartedOverMarkerWithRealId()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(StatePath, "{not json");
        var first = new Fixture(StatePath);
        await first.Track(default);
        Assert.True(first.Store.IsQuarantined());
        Assert.Contains("\"agent_id\":\"agent-a\"", File.ReadAllText(StatePath));
        Assert.Contains("\"reset\":\"unreadable\"", File.ReadAllText(StatePath));

        var restarted = new Fixture(StatePath);
        await restarted.Track(default);
        return restarted;
    }

    [Fact]
    public async Task ResetMarkerWithRealId_SignedLiftDoesNotRestoreQuarantineAfterRestart()
    {
        var f = await RestartedOverMarkerWithRealId();
        Assert.True(f.Store.IsQuarantined("agent-a"));

        Assert.Equal("DONE", (await f.Handle("c1", P(1, ""","quarantine":{"active":false}"""))).Status);

        Assert.False(f.Store.IsQuarantined("agent-a"));
        Assert.DoesNotContain("reset", File.ReadAllText(StatePath));
        var second = new AgentSignedStateStore(StatePath);
        Assert.False(second.IsQuarantined("agent-a"));
        Assert.Equal(1, second.Load("agent-a").StateSeq);
    }

    [Fact]
    public async Task ResetMarkerWithRealId_SignedWriteWithoutQuarantineFieldStartsFromEmptyState()
    {
        var f = await RestartedOverMarkerWithRealId();

        Assert.Equal("DONE", (await f.Handle("c1", P(7, ""","registration_state":"claimed" """))).Status);

        Assert.False(f.Store.IsQuarantined("agent-a"));
        var second = new AgentSignedStateStore(StatePath);
        Assert.False(second.IsQuarantined("agent-a"));
        var state = second.Load("agent-a");
        Assert.Equal(7, state.StateSeq);
        Assert.Equal("claimed", state.RegistrationState);
        Assert.False(state.QuarantineActive);
        Assert.Null(state.Reset);
    }

    [Fact]
    public async Task ResetMarkerWithRealId_LoadIsEmptyWhileQuarantineStaysEnforced()
    {
        var f = await RestartedOverMarkerWithRealId();

        Assert.Equal(0, f.Store.Load("agent-a").StateSeq);
        Assert.False(f.Store.Load("agent-a").QuarantineActive);
        Assert.Null(f.Store.Load("agent-a").Reset);
        Assert.True(f.Store.IsQuarantined("agent-a"));
        Assert.True(f.Store.IsQuarantined());
    }

    [Fact]
    public void CorruptFile_WhenTheReplacementCannotBeWritten_StaysQuarantinedInMemory()
    {
        Directory.CreateDirectory(_dir);
        // The set-aside name (+19 chars) fits the 255-char file name limit; the temp name (+37 chars) does not.
        var longPath = Path.Combine(_dir, new string('s', 230));
        File.WriteAllText(longPath, "{not json");
        var store = new AgentSignedStateStore(longPath);

        Assert.True(store.IsQuarantined("agent-a"));
        Assert.True(store.IsQuarantined("agent-b"));
        Assert.False(File.Exists(longPath));
        Assert.Single(Directory.GetFiles(_dir, "*.corrupt-*"));
    }

    [Fact]
    public void ForeignResetValue_IsTreatedAsCorrupt()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(StatePath,
            """{"schema":"cerberus.agent-state.v1","state":{"agent_id":"agent-a","state_seq":3,"quarantine_active":false,"registration_state":null,"reset":"other"}}""");

        var store = new AgentSignedStateStore(StatePath);

        Assert.True(store.IsQuarantined("agent-a"));
        Assert.Equal(0, store.Load("agent-a").StateSeq);
        Assert.Single(Directory.GetFiles(_dir, AgentSignedStateStore.FileName + ".corrupt-*"));
    }

    private sealed class Fixture
    {
        private readonly Func<CancellationToken, Task<string>> _track;

        public Fixture(string statePath, bool failQuiesce = false)
        {
            Store = new AgentSignedStateStore(statePath);
            _track = Store.Track(_ => AgentIdUnavailable ? throw new InvalidOperationException("credential cleared") : Task.FromResult(AgentId));
            Lifecycle = new AgentLifecycleController(new InMemoryAgentLifecycleStateStore(), Secrets, quiesce: _ =>
            {
                Quiesces++;
                return failQuiesce ? throw new IOException("quiesce failed") : Task.CompletedTask;
            });
            Handler = new AgentStateCommandHandler(Store, _track, Lifecycle, () => Cancels++);
        }

        public string AgentId { get; set; } = "agent-a";
        public bool AgentIdUnavailable { get; set; }
        public AgentSignedStateStore Store { get; }
        public AgentStateCommandHandler Handler { get; }
        public AgentLifecycleController Lifecycle { get; }
        public Secrets Secrets { get; } = new();
        public int Cancels { get; private set; }
        public int Quiesces { get; private set; }

        public Task<string> Track(CancellationToken ct) => _track(ct);

        public Task<CommandResult> Handle(string id, string payloadJson)
            => Handler.HandleAsync(
                new AgentCommand(id, "agent_state", id, JsonDocument.Parse(payloadJson).RootElement.Clone()),
                CancellationToken.None);
    }

    private sealed class Secrets : ISecretStore
    {
        public bool Cleared { get; private set; }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((new AgentIdentity("agent-a", "t1"), "refresh", "key", "https://backend.invalid", (string?)null, (string?)null));

        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
            => Task.CompletedTask;

        public Task ClearAsync(CancellationToken ct)
        {
            Cleared = true;
            return Task.CompletedTask;
        }
    }
}
