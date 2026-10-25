using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Unit/support evidence for the F1 fix: the signed-state and replay stores fail closed on untrusted storage,
// default to <DataDir>\Privileged, and a signed revoke survives a restart. The real Privileged ACLs, the
// SYSTEM-only directory creation and the ServiceMode wiring need a service install (acceptance tier, not run here).
public sealed class ProtectedStateStoreTests : IDisposable
{
    private const long T0 = EnvelopeHarness.T0;
    private const string Agent = "agent-a";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTime _time = new(T0);

    private string StatePath => Path.Combine(_dir, AgentSignedStateStore.FileName);
    private string ReplayPath => Path.Combine(_dir, CommandReplayStore.FileName);

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

    [Fact]
    public void DefaultPaths_AreUnderThePrivilegedDirectoryOfTheDataDir()
    {
        var privileged = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AgentInstallIdentity.DataDirName, "Privileged");

        Assert.Equal(Path.Combine(privileged, "agent-state.v1.json"), AgentSignedStateStore.DefaultPath());
        Assert.Equal(Path.Combine(privileged, "command-envelopes.v1.json"), CommandReplayStore.DefaultPath());
    }

    // ---- provenance: signed state ----

    [Fact]
    public void SignedState_UsersWritableDacl_IsRejectedNotParsedNotMoved()
    {
        SeedState(seq: 9);
        Assert.False(new AgentSignedStateStore(StatePath).IsQuarantined(Agent));
        GrantUsersWrite(StatePath);

        var store = new AgentSignedStateStore(StatePath, enforceFileProvenance: true);

        Assert.True(store.IsQuarantined(Agent));
        Assert.True(store.IsQuarantined());
        Assert.Equal(0, store.Load(Agent).StateSeq);
        Assert.True(File.Exists(StatePath));
        Assert.Empty(Directory.GetFiles(_dir, "*.corrupt-*"));
    }

    [Fact]
    public void SignedState_UntrustedOwner_IsRejectedEvenWithAProtectedDacl()
    {
        SeedState(seq: 9);
        ProtectToSystemAndAdministrators(StatePath);

        var store = new AgentSignedStateStore(StatePath, enforceFileProvenance: true);

        // Created by the test user: untrusted owner unless the shell is elevated (then Administrators owns it).
        Assert.Equal(!OwnerIsTrusted(StatePath), store.IsQuarantined(Agent));
        Assert.Equal(OwnerIsTrusted(StatePath) ? 9 : 0, store.Load(Agent).StateSeq);
    }

    [Fact]
    public void SignedState_RejectedFile_IsReplacedByTheNextSignedWrite()
    {
        SeedState(seq: 9);
        GrantUsersWrite(StatePath);
        var store = new AgentSignedStateStore(StatePath, enforceFileProvenance: true);
        Assert.True(store.IsQuarantined(Agent));

        Assert.True(store.TrySave(new AgentSignedState(Agent, 1, false, null)));

        Assert.False(store.IsQuarantined(Agent));
        Assert.Equal(1, store.Load(Agent).StateSeq);
        Assert.False(new AgentSignedStateStore(StatePath).IsQuarantined(Agent));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SignedState_DirectoryAtThePath_IsRefused(bool enforce)
    {
        Directory.CreateDirectory(StatePath);

        var store = new AgentSignedStateStore(StatePath, enforceFileProvenance: enforce);

        Assert.True(store.IsQuarantined(Agent));
        Assert.True(Directory.Exists(StatePath));
        Assert.False(store.TrySave(new AgentSignedState(Agent, 1, false, null)));
        Assert.True(store.IsQuarantined(Agent));
    }

    // ---- provenance: replay store ----

    [Fact]
    public void ReplayStore_UsersWritableDacl_ResetsWithoutReadingOrMovingTheFile()
    {
        StoreFileWriter.Write(ReplayPath, 0, new[] { StoreFileWriter.Record(Agent, "c1", "n1", EnvelopeRecordStates.Reserved, T0, T0 + 120) });
        Assert.NotNull(new CommandReplayStore(ReplayPath, _time).Find(Agent, "c1"));
        GrantUsersWrite(ReplayPath);

        var store = new CommandReplayStore(ReplayPath, _time, enforceFileProvenance: true);

        Assert.Null(store.Find(Agent, "c1"));
        Assert.Equal(T0, store.ResetAt);
        Assert.Empty(Directory.GetFiles(_dir, "*.corrupt-*"));
        Assert.Equal(ReplayReserveOutcome.Reserved,
            store.TryReserve(StoreFileWriter.Record(Agent, "c2", "n2", EnvelopeRecordStates.Reserved, T0, T0 + 120)));
    }

    [Fact]
    public void ReplayStore_UntrustedOwner_ResetsEvenWithAProtectedDacl()
    {
        StoreFileWriter.Write(ReplayPath, 0, new[] { StoreFileWriter.Record(Agent, "c1", "n1", EnvelopeRecordStates.Reserved, T0, T0 + 120) });
        ProtectToSystemAndAdministrators(ReplayPath);

        var store = new CommandReplayStore(ReplayPath, _time, enforceFileProvenance: true);

        Assert.Equal(OwnerIsTrusted(ReplayPath), store.Find(Agent, "c1") is not null);
        Assert.Equal(OwnerIsTrusted(ReplayPath) ? 0 : T0, store.ResetAt);
    }

    [Fact]
    public void ReplayStore_DirectoryAtThePath_NeverReservesAndKeepsTheDirectory()
    {
        Directory.CreateDirectory(ReplayPath);

        var store = new CommandReplayStore(ReplayPath, _time);

        Assert.Equal(T0, store.ResetAt);
        Assert.Equal(ReplayReserveOutcome.Unavailable,
            store.TryReserve(StoreFileWriter.Record(Agent, "c1", "n1", EnvelopeRecordStates.Reserved, T0, T0 + 120)));
        Assert.True(Directory.Exists(ReplayPath));
    }

    // ---- durable signed revoke ----

    [Fact]
    public async Task Revoke_SurvivesRestartsUntilTheResultPostSucceedsThenRetires()
    {
        var lifecycle = new InMemoryAgentLifecycleStateStore();
        var first = new Rig(_dir, lifecycle, _time);
        Assert.Equal("DONE", (await first.Handle("c1", """{"state_seq":1,"revoke":{"reason_code":"agent_revoked"}}""")).Status);
        SeedDoneResult("c1", submitted: false);

        // Restart 1: the POST fails, nothing may retire and the revoke stays quarantined and stored.
        await using (var second = new Rig(_dir, lifecycle, _time))
        {
            second.Backend.Respond = (_, _) => Task.FromResult(System.Net.HttpStatusCode.ServiceUnavailable);
            Assert.True(second.Store.IsQuarantined(Agent));
            Assert.Equal(new AgentPendingRevoke("c1", "agent_revoked"), second.Store.Load(Agent).PendingRevoke);
            second.Queue.Start();
            second.Queue.SignalHeartbeat();
            await Wait.UntilAsync(() => second.Backend.Results.Count == 1, "first result POST");
            await second.Queue.StopAsync();
            Assert.Equal(AgentLifecycleState.Active, (await second.Lifecycle.LoadAsync(default)).State);
            Assert.Equal(0, second.Cancels);
        }

        // Restart 2: the POST gets a 2xx, then the lifecycle is Retired and the pending revoke is cleared.
        await using var third = new Rig(_dir, lifecycle, _time);
        Assert.True(third.Store.IsQuarantined(Agent));
        third.Queue.Start();
        third.Queue.SignalHeartbeat();
        await Wait.UntilAsync(() => third.Cancels > 0, "revoke follow-up");
        await third.Queue.StopAsync();

        Assert.Single(third.Backend.Results);
        Assert.Equal("c1", third.Backend.Results[0].CommandId);
        var snapshot = await third.Lifecycle.LoadAsync(default);
        Assert.Equal(AgentLifecycleState.Retired, snapshot.State);
        Assert.Equal("agent_revoked", snapshot.ReasonCode);
        Assert.True(third.Replay.Find(Agent, "c1")!.ResultSubmitted);
        Assert.Null(new AgentSignedStateStore(StatePath).Load(Agent).PendingRevoke);
    }

    [Fact]
    public async Task Recovery_AfterACrashFollowingTheSuccessfulPost_RetiresAndClears()
    {
        var lifecycle = new InMemoryAgentLifecycleStateStore();
        await new Rig(_dir, lifecycle, _time).Handle("c1", """{"state_seq":1,"revoke":{"reason_code":"agent_deactivated"}}""");
        SeedDoneResult("c1", submitted: true);

        await using var restarted = new Rig(_dir, lifecycle, _time);
        await restarted.Handler.RecoverPendingRevokeAsync(restarted.Replay, default);

        var snapshot = await restarted.Lifecycle.LoadAsync(default);
        Assert.Equal(AgentLifecycleState.Retired, snapshot.State);
        Assert.Equal("agent_deactivated", snapshot.ReasonCode);
        Assert.Equal(1, restarted.Cancels);
        Assert.Null(new AgentSignedStateStore(StatePath).Load(Agent).PendingRevoke);
        Assert.Empty(restarted.Backend.Requests);
    }

    [Fact]
    public async Task Recovery_LeavesAResultStillWaitingInTheOutboxToTheOutbox()
    {
        var lifecycle = new InMemoryAgentLifecycleStateStore();
        await new Rig(_dir, lifecycle, _time).Handle("c1", """{"state_seq":1,"revoke":{"reason_code":"agent_revoked"}}""");
        SeedDoneResult("c1", submitted: false);

        await using var restarted = new Rig(_dir, lifecycle, _time);
        await restarted.Handler.RecoverPendingRevokeAsync(restarted.Replay, default);

        Assert.Equal(AgentLifecycleState.Active, (await restarted.Lifecycle.LoadAsync(default)).State);
        Assert.Equal(0, restarted.Cancels);
        Assert.True(restarted.Store.IsQuarantined(Agent));
        Assert.NotNull(restarted.Store.Load(Agent).PendingRevoke);
    }

    [Fact]
    public async Task Recovery_WithoutAReplayRecordAndAReadableStore_AppliesTheRevoke()
    {
        var lifecycle = new InMemoryAgentLifecycleStateStore();
        await new Rig(_dir, lifecycle, _time).Handle("c1", """{"state_seq":1,"revoke":{"reason_code":"agent_revoked"}}""");

        await using var restarted = new Rig(_dir, lifecycle, _time);
        await restarted.Handler.RecoverPendingRevokeAsync(restarted.Replay, default);

        Assert.Equal(AgentLifecycleState.Retired, (await restarted.Lifecycle.LoadAsync(default)).State);
        Assert.Null(restarted.Store.Load(Agent).PendingRevoke);
    }

    [Fact]
    public async Task Recovery_WithAnUnavailableReplayStore_KeepsTheRevokePending()
    {
        var lifecycle = new InMemoryAgentLifecycleStateStore();
        await new Rig(_dir, lifecycle, _time).Handle("c1", """{"state_seq":1,"revoke":{"reason_code":"agent_revoked"}}""");
        Directory.CreateDirectory(ReplayPath);

        await using var restarted = new Rig(_dir, lifecycle, _time);
        await restarted.Handler.RecoverPendingRevokeAsync(restarted.Replay, default);

        Assert.Equal(AgentLifecycleState.Active, (await restarted.Lifecycle.LoadAsync(default)).State);
        Assert.NotNull(restarted.Store.Load(Agent).PendingRevoke);
    }

    // ---- helpers ----

    private void SeedState(long seq)
    {
        Directory.CreateDirectory(_dir);
        Assert.True(new AgentSignedStateStore(StatePath).TrySave(new AgentSignedState(Agent, seq, false, null)));
    }

    private void SeedDoneResult(string id, bool submitted)
        => StoreFileWriter.Write(ReplayPath, 0, new[]
        {
            StoreFileWriter.Record(Agent, id, "n-" + id, EnvelopeRecordStates.Done, T0, T0 + 120, "e30=", submitted)
                with { Type = EnvelopeTypes.AgentState },
        });

    private static bool OwnerIsTrusted(string path)
    {
        var owner = new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        return owner?.Value is "S-1-5-18" or "S-1-5-32-544";
    }

    private static void GrantUsersWrite(string path)
    {
        var file = new FileInfo(path);
        var security = file.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Write, AccessControlType.Allow));
        file.SetAccessControl(security);
    }

    private static void ProtectToSystemAndAdministrators(string path)
    {
        var acl = new FileSecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(acl);
    }

    /// <summary>One "process": stores, handler, lifecycle controller and queue rebuilt from the files in the directory.</summary>
    private sealed class Rig : IAsyncDisposable
    {
        private readonly HttpClient _http;
        private int _cancels;

        public Rig(string dir, InMemoryAgentLifecycleStateStore lifecycleStore, TimeProvider time)
        {
            Store = new AgentSignedStateStore(Path.Combine(dir, AgentSignedStateStore.FileName));
            var track = Store.Track(_ => Task.FromResult(Agent));
            Lifecycle = new AgentLifecycleController(lifecycleStore, new Secrets());
            Handler = new AgentStateCommandHandler(Store, track, Lifecycle, () => Interlocked.Increment(ref _cancels), null, () => { }, new AgentRevokeFinalResults());
            Replay = new CommandReplayStore(Path.Combine(dir, CommandReplayStore.FileName), time);
            _http = new HttpClient(Backend) { BaseAddress = new Uri("http://backend.test") };
            var api = new AgentApiClient(_http, new Secrets(), new Token(), new Signer());
            Queue = new EnvelopeExecutionQueue(api, Replay, new ICommandHandler[] { Handler }, track, Store.IsQuarantined, time);
        }

        public AgentSignedStateStore Store { get; }
        public AgentLifecycleController Lifecycle { get; }
        public AgentStateCommandHandler Handler { get; }
        public CommandReplayStore Replay { get; }
        public EnvelopeExecutionQueue Queue { get; }
        public FakeBackend Backend { get; } = new();
        public int Cancels => Volatile.Read(ref _cancels);

        public Task<CommandResult> Handle(string id, string payloadJson)
            => Handler.HandleAsync(
                new AgentCommand(id, "agent_state", id, JsonDocument.Parse(payloadJson).RootElement.Clone()), CancellationToken.None);

        public async ValueTask DisposeAsync()
        {
            await Queue.StopAsync();
            _http.Dispose();
        }
    }

    private sealed class Secrets : ISecretStore
    {
        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((new AgentIdentity(Agent, "t1"), "refresh", "key", "http://backend.test", (string?)null, (string?)null));

        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
            => Task.CompletedTask;

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class Token : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("token");

        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class Signer : IRequestSigner
    {
        public string ComputeBodyHash(byte[] bodyBytes) => "hash";

        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash)
            => $"{method}:{path}:{nonce}:{timestamp}:{bodyHash}";

        public string Sign(string canonical) => "signature";
    }
}
