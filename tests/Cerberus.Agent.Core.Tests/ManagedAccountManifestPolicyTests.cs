using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.Core.Tests;

public sealed class ManagedAccountManifestPolicyTests
{
    private static readonly ManagedAccountEntry Account = new("assignment", "account", "member", "cerb_sennu_k7m2q6x4", "marker", "active");
    private static readonly AgentIdentity Identity = new("agent", "tenant");
    private static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-09-06T12:00:00Z");

    [Fact]
    public void LegacyOwnership_RequiresExplicitAdoptionOptIn_AndExactTuple()
    {
        var legacy = new ManagedLocalOwnership(Account, "", "", "", "current-sid");
        Assert.False(legacy.MatchesIdentity(Identity, Account));
        Assert.True(legacy.MatchesIdentity(Identity, Account, allowLegacy: true));
        Assert.False(legacy.MatchesIdentity(Identity, Account with { UserId = "foreign" }, allowLegacy: true));
        Assert.False((legacy with { AgentId = "foreign" }).MatchesIdentity(Identity, Account, allowLegacy: true));
        var bound = legacy with { AgentId = "agent", TenantId = "tenant", StoredSid = "current-sid" };
        Assert.True(bound.MatchesIdentity(Identity, Account));
        Assert.False((bound with { CurrentSid = "replacement" }).MatchesIdentity(Identity, Account));
    }

    [Fact]
    public async Task ChangedHeartbeatHash_RefreshesImmediatelyBeforeQueuedCreate()
    {
        var now = Start;
        var manifest = Manifest(now, status: "planned");
        var fetches = 0;
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(), _ =>
        {
            fetches++;
            return Task.FromResult(manifest);
        }, new AccountStore(), now: () => now);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        now = now.AddSeconds(1);
        manifest = Manifest(now, status: "create_queued");
        await policy.RefreshAsync(Heartbeat(manifest), default);
        Assert.Equal(2, fetches);
        Assert.Equal("DONE", (await policy.ExecuteAuthorizedAsync(Account,
            () => Task.FromResult(new CommandResult("DONE", 0, null, null, null)), default)).Status);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        Assert.Equal(2, fetches);
    }

    [Fact]
    public async Task PythonCanonicalDeleteCharacterEscape_IsAccepted()
    {
        var manifest = Manifest(Start, deleteCharacter: true);
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(),
            _ => Task.FromResult(manifest), new AccountStore(), now: () => Start);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        Assert.Equal("DONE", (await policy.ExecuteAuthorizedAsync(manifest.Accounts[0],
            () => Task.FromResult(new CommandResult("DONE", 0, null, null, null)), default)).Status);
    }

    [Fact]
    public async Task EnrollmentChangesDuringFetch_PreventReconciliationAndCreate()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var manifest = Manifest(Start);
        var store = new AccountStore();
        var policy = new ManagedAccountManifestPolicy(Identity, state, async _ =>
        {
            await state.SaveAsync(new AgentLifecycleSnapshot(AgentLifecycleState.Retired), default);
            return manifest;
        }, store, now: () => Start);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        Assert.Equal(0, store.Reconciliations);
        Assert.Equal("FAILED", (await policy.ExecuteAuthorizedAsync(Account,
            () => throw new InvalidOperationException("Stale enrollment executed"), default)).Status);
    }

    [Fact]
    public async Task CancelledRefresh_DiscardsPreviouslyCachedAuthority()
    {
        var now = Start;
        var manifest = Manifest(now);
        var calls = 0;
        using var caller = new CancellationTokenSource();
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(), _ =>
        {
            if (++calls == 1) return Task.FromResult(manifest);
            caller.Cancel();
            throw new OperationCanceledException(caller.Token);
        },
            new AccountStore(), now: () => now);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        now = now.AddSeconds(61);
        manifest = Manifest(now, status: "create_queued");
        await Assert.ThrowsAsync<OperationCanceledException>(() => policy.RefreshAsync(Heartbeat(manifest), caller.Token));
        Assert.Equal("FAILED", (await policy.ExecuteAuthorizedAsync(Account,
            () => throw new InvalidOperationException("Cancelled authority executed"), default)).Status);
    }

    [Fact]
    public async Task Reconciliation_DisablesOnlyExactOwnedMissingOrDisabledAccounts()
    {
        var owned = new ManagedLocalOwnership(Account, "agent", "tenant", "sid", "sid");
        var store = new LocalAccountStore([
            owned,
            owned with { AgentId = "foreign" },
            owned with { TenantId = "foreign" },
            owned with { StoredSid = "" },
            owned with { CurrentSid = "replaced-user" },
            owned with { Account = Account with { Username = "Administrator" } }
        ]);
        var reconciler = LocalUserCommandHandlers.CreateManifestReconciler(store: store);
        await reconciler.ReconcileAsync(Identity, [Account], default);
        Assert.Empty(store.Disabled);
        await reconciler.ReconcileAsync(Identity, [Account with { Status = "disabled" }], default);
        Assert.Equal([owned], store.Disabled);
        store.Disabled.Clear();
        await reconciler.ReconcileAsync(Identity, [], default);
        Assert.Equal([owned], store.Disabled);
    }

    [Theory]
    [InlineData("active", true, false, true)]
    [InlineData("disabled_rotate_queued", false, true, true)]
    [InlineData("disabled_rotate_queued", false, false, false)]
    [InlineData("disabled_rotate_queued", true, true, false)]
    [InlineData("disabled", false, true, false)]
    public async Task MutationAuthority_UsesExplicitIntentWithoutBroadeningReconciliation(
        string manifestStatus, bool enableAccount, bool enableAccountExplicit, bool expectedAllowed)
    {
        var now = Start;
        var manifest = Manifest(now, status: manifestStatus);
        var executions = 0;
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(),
            _ => Task.FromResult(manifest), new AccountStore(), now: () => now);
        await policy.RefreshAsync(Heartbeat(manifest), default);

        var result = await policy.ExecuteAuthorizedAsync(Account, enableAccount, enableAccountExplicit, () =>
        {
            executions++;
            return Task.FromResult(new CommandResult("DONE", 0, null, null, null));
        }, default);

        Assert.Equal(expectedAllowed ? "DONE" : "FAILED", result.Status);
        Assert.Equal(expectedAllowed ? 1 : 0, executions);
        Assert.Equal(manifestStatus is "active" or "planned" or "create_queued",
            ManagedAccountManifestPolicy.Allows(new(
            "assignment", "account", "member", "cerb_sennu_k7m2q6x4", "marker", manifestStatus)));
    }

    [Fact]
    public async Task RemovedAssignment_DisablesPreviouslyAuthorizedAccount_AndDeniesFurtherExecution()
    {
        var now = Start;
        var store = new AccountStore();
        var manifest = Manifest(now);
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(),
            _ => Task.FromResult(manifest), store, now: () => now);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        var allowed = await policy.ExecuteAuthorizedAsync(Account, () =>
        {
            store.Enabled = true;
            return Task.FromResult(new CommandResult("DONE", 0, null, null, null));
        }, default);
        Assert.Equal("DONE", allowed.Status);
        Assert.True(store.Enabled);

        now = now.AddSeconds(61);
        manifest = Manifest(now, empty: true);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        Assert.False(store.Enabled);
        Assert.Equal("FAILED", (await policy.ExecuteAuthorizedAsync(Account,
            () => throw new InvalidOperationException("Revoked operation executed"), default)).Status);
    }

    [Fact]
    public async Task ExpiredOrUnavailableAuthority_DeniesCreate_AndBoundsFetchRetries()
    {
        var now = Start;
        var manifest = Manifest(now);
        var fetches = 0;
        var store = new AccountStore();
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(), _ =>
        {
            fetches++;
            return fetches == 1 ? Task.FromResult(manifest) : throw new HttpRequestException("offline");
        }, store, now: () => now);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        now = Start.AddSeconds(61);
        manifest = Manifest(now, status: "create_queued");
        await policy.RefreshAsync(Heartbeat(manifest), default);
        manifest = Manifest(now, status: "planned");
        await policy.RefreshAsync(Heartbeat(manifest), default);
        Assert.Equal(2, fetches);
        Assert.False(store.Enabled);
        Assert.Equal("FAILED", (await policy.ExecuteAuthorizedAsync(Account,
            () => throw new InvalidOperationException("Offline operation executed"), default)).Status);
    }

    [Theory]
    [InlineData("hash")]
    [InlineData("identity")]
    [InlineData("expired")]
    [InlineData("generation")]
    [InlineData("disabled")]
    public async Task InvalidOrStaleAuthority_DeniesExecution(string scenario)
    {
        var now = Start;
        var manifest = Manifest(now);
        var state = new InMemoryAgentLifecycleStateStore();
        var policy = new ManagedAccountManifestPolicy(Identity, state,
            _ => Task.FromResult(manifest), new AccountStore(), now: () => now);
        if (scenario == "disabled") manifest = Manifest(now, status: "disabled");
        var heartbeat = Heartbeat(manifest);
        if (scenario == "hash") heartbeat = heartbeat with { ManagedAccountManifestHash = "wrong" };
        await policy.RefreshAsync(heartbeat, default);
        if (scenario == "expired") now = now.AddSeconds(301);
        if (scenario == "generation") await state.SaveAsync(new AgentLifecycleSnapshot(AgentLifecycleState.Retired), default);
        var requested = scenario == "identity" ? Account with { ManagedAccountId = "foreign" } : Account;
        var result = await policy.ExecuteAuthorizedAsync(requested,
            () => throw new InvalidOperationException("Denied operation executed"), default);
        Assert.Equal("FAILED", result.Status);
        var postVerify = JsonSerializer.SerializeToElement(result.PostVerify);
        Assert.Equal("managed_account_manifest_required", postVerify.GetProperty("code").GetString());
        Assert.Equal("before_execution", postVerify.GetProperty("execution_stage").GetString());
        Assert.Equal(requested.ManagedAccountId, postVerify.GetProperty("managed_account_id").GetString());
        Assert.Equal(requested.AssignmentId, postVerify.GetProperty("assignment_id").GetString());
        Assert.Equal(requested.MarkerId, postVerify.GetProperty("marker_id").GetString());
    }

    [Fact]
    public async Task ExpiryDuringMutation_DisablesAccountBeforeReturningFailure()
    {
        var now = Start;
        var store = new AccountStore();
        var manifest = Manifest(now);
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(),
            _ => Task.FromResult(manifest), store, now: () => now);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        var result = await policy.ExecuteAuthorizedAsync(Account, () =>
        {
            store.Enabled = true;
            now = now.AddSeconds(301);
            return Task.FromResult(new CommandResult("DONE", 0, null, null,
                new { code = "created", encrypted_password = "secret", rdp_credential = new { value = "secret" } }));
        }, default);
        Assert.Equal("FAILED", result.Status);
        Assert.False(store.Enabled);
        var postVerify = JsonSerializer.SerializeToElement(result.PostVerify);
        Assert.Equal("after_execution", postVerify.GetProperty("execution_stage").GetString());
        Assert.Equal("created", postVerify.GetProperty("mutation_result_code").GetString());
        Assert.Equal("DONE", postVerify.GetProperty("mutation_result_status").GetString());
        Assert.Equal("attempted", postVerify.GetProperty("compensation_status").GetString());
        Assert.DoesNotContain("encrypted_password", postVerify.GetRawText(), StringComparison.Ordinal);
        Assert.DoesNotContain("rdp_credential", postVerify.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpiryDuringMutation_ReportsFailedCompensationWithoutClaimingDisable()
    {
        var now = Start;
        var store = new AccountStore { ThrowOnEmptyReconciliation = true };
        var manifest = Manifest(now);
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(),
            _ => Task.FromResult(manifest), store, now: () => now);
        await policy.RefreshAsync(Heartbeat(manifest), default);

        var result = await policy.ExecuteAuthorizedAsync(Account, () =>
        {
            store.Enabled = true;
            now = now.AddSeconds(301);
            return Task.FromResult(new CommandResult("DONE", 0, null, null,
                new { code = "created", encrypted_password = "secret" }));
        }, default);

        var postVerify = JsonSerializer.SerializeToElement(result.PostVerify);
        Assert.Equal("after_execution", postVerify.GetProperty("execution_stage").GetString());
        Assert.Equal("failed", postVerify.GetProperty("compensation_status").GetString());
        Assert.DoesNotContain("verified", postVerify.GetRawText(), StringComparison.OrdinalIgnoreCase);
        Assert.True(store.Enabled);
    }

    [Fact]
    public async Task ExpiryDuringPreflightRefusal_DoesNotPromoteItToCompletedMutation()
    {
        var now = Start;
        var store = new AccountStore();
        var manifest = Manifest(now);
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(),
            _ => Task.FromResult(manifest), store, now: () => now);
        await policy.RefreshAsync(Heartbeat(manifest), default);

        var result = await policy.ExecuteAuthorizedAsync(Account, () =>
        {
            now = now.AddSeconds(301);
            return Task.FromResult(new CommandResult(
                "FAILED",
                2,
                null,
                "Rate limited.",
                new
                {
                    code = "local_user_rate_limited",
                    execution_stage = "before_execution",
                }));
        }, default);

        var postVerify = JsonSerializer.SerializeToElement(result.PostVerify);
        Assert.Equal("managed_account_manifest_required", postVerify.GetProperty("code").GetString());
        Assert.Equal("unknown", postVerify.GetProperty("execution_stage").GetString());
        Assert.Equal("local_user_rate_limited", postVerify.GetProperty("mutation_result_code").GetString());
        Assert.Equal("FAILED", postVerify.GetProperty("mutation_result_status").GetString());
        Assert.Equal("attempted", postVerify.GetProperty("compensation_status").GetString());
    }

    [Fact]
    public async Task CachedSuccess_CannotBypassCurrentManifestDeny()
    {
        var now = Start;
        var manifest = Manifest(now);
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(),
            _ => Task.FromResult(manifest), new AccountStore(), now: () => now);
        await policy.RefreshAsync(Heartbeat(manifest), default);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        try
        {
            var handler = new GatedHandler(policy);
            var dispatcher = new CommandDispatcher([handler], new IdempotencyCache(path, 100, TimeSpan.FromHours(1)));
            var command = new AgentCommand("cmd", handler.Type, "idempotency", new { });
            Assert.Equal("DONE", (await dispatcher.DispatchAsync(command, default)).Status);
            now = now.AddSeconds(301);
            Assert.Equal("FAILED", (await dispatcher.DispatchAsync(command, default)).Status);
            Assert.Equal(1, handler.Executions);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task ManifestRecovery_RequiresNewCommand_CachedCreateCannotRestoreDisabledAccount()
    {
        var now = Start;
        var manifest = Manifest(now);
        var unavailable = false;
        var store = new AccountStore();
        var policy = new ManagedAccountManifestPolicy(Identity, new InMemoryAgentLifecycleStateStore(),
            _ => unavailable ? throw new HttpRequestException("offline") : Task.FromResult(manifest),
            store, now: () => now);
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        try
        {
            var handler = new GatedHandler(policy, () => store.Enabled = true);
            var dispatcher = new CommandDispatcher([handler], new IdempotencyCache(path, 100, TimeSpan.FromHours(1)));
            var command = new AgentCommand("original", handler.Type, "original", new { });
            await policy.RefreshAsync(Heartbeat(manifest), default);
            Assert.Equal("DONE", (await dispatcher.DispatchAsync(command, default)).Status);

            now = now.AddSeconds(301);
            manifest = Manifest(now);
            unavailable = true;
            await policy.RefreshAsync(Heartbeat(manifest), default);
            Assert.False(store.Enabled);
            Assert.Equal("FAILED", (await dispatcher.DispatchAsync(command, default)).Status);

            now = now.AddSeconds(61);
            manifest = Manifest(now);
            unavailable = false;
            await policy.RefreshAsync(Heartbeat(manifest), default);
            Assert.False(store.Enabled);
            Assert.Equal("DONE", (await dispatcher.DispatchAsync(command, default)).Status);
            Assert.False(store.Enabled);
            Assert.Equal(1, handler.Executions);

            var recovery = new AgentCommand("recovery", handler.Type, "recovery", new { });
            Assert.Equal("DONE", (await dispatcher.DispatchAsync(recovery, default)).Status);
            Assert.True(store.Enabled);
            Assert.Equal(2, handler.Executions);

            manifest = Manifest(now, empty: true);
            await policy.RefreshAsync(Heartbeat(manifest), default);
            Assert.False(store.Enabled);
            Assert.Equal("FAILED", (await dispatcher.DispatchAsync(
                new AgentCommand("revoked", handler.Type, "revoked", new { }), default)).Status);
            Assert.False(store.Enabled);
            Assert.Equal(2, handler.Executions);
        }
        finally { File.Delete(path); }
    }

    private static ManagedAccountManifest Manifest(DateTimeOffset now, bool empty = false, string status = "active", bool deleteCharacter = false)
    {
        const string canonical = "[{\"assignment_id\":\"assignment\",\"managed_account_id\":\"account\",\"marker_id\":\"marker\",\"status\":\"active\",\"user_id\":\"member\",\"username\":\"cerb_sennu_k7m2q6x4\"}]";
        var serialized = canonical.Replace("\"active\"", "\"" + status + "\"");
        if (deleteCharacter) serialized = serialized.Replace("member", "member\\u007f");
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(empty ? "[]" : serialized))).ToLowerInvariant();
        return new(hash[..16], hash, now.AddSeconds(300), true, empty ? [] :
            [Account with { Status = status, UserId = deleteCharacter ? "member\u007f" : "member" }]);
    }

    private static HeartbeatResponse Heartbeat(ManagedAccountManifest manifest)
        => JsonSerializer.Deserialize<HeartbeatResponse>("{}")! with
        {
            RequireManifestBeforeUnlock = true, ManifestVersion = manifest.Version,
            ManagedAccountManifestHash = manifest.Hash, ManifestFreshUntil = manifest.FreshUntil.ToString("O")
        };

    private sealed class AccountStore : IManagedAccountReconciler
    {
        public bool Enabled { get; set; } = true;
        public bool ThrowOnEmptyReconciliation { get; init; }
        public int Reconciliations { get; private set; }
        public Task ReconcileAsync(AgentIdentity identity, IReadOnlyList<ManagedAccountEntry> allowed, CancellationToken ct)
        {
            Assert.Equal(Identity, identity);
            Reconciliations++;
            if (ThrowOnEmptyReconciliation && allowed.Count == 0)
                throw new InvalidOperationException("compensation unavailable");
            if (!allowed.Contains(Account)) Enabled = false;
            return Task.CompletedTask;
        }
    }

    private sealed class LocalAccountStore(IReadOnlyList<ManagedLocalOwnership> accounts) : IManagedLocalAccountStore
    {
        public List<ManagedLocalOwnership> Disabled { get; } = [];
        public IReadOnlyList<ManagedLocalOwnership> ReadAccounts() => accounts;
        public void Disable(ManagedLocalOwnership ownership) => Disabled.Add(ownership);
    }

    private sealed class GatedHandler(ManagedAccountManifestPolicy policy, Action? execute = null) : ICommandHandler, ICommandExecutionGate
    {
        public string Type => "windows.local_user.create";
        public int Executions { get; private set; }
        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
            => ExecuteAuthorizedAsync(command, () => HandleAuthorizedAsync(command, ct), ct);
        public Task<CommandResult> ExecuteAuthorizedAsync(AgentCommand command, Func<Task<CommandResult>> execute, CancellationToken ct)
            => policy.ExecuteAuthorizedAsync(Account, execute, ct);
        public Task<CommandResult> HandleAuthorizedAsync(AgentCommand command, CancellationToken ct)
        {
            Executions++;
            execute?.Invoke();
            return Task.FromResult(new CommandResult("DONE", 0, null, null, null));
        }
    }
}
