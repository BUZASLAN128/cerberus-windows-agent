using Cerberus.Agent.Core;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Control;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentStateRevokeGuardTests
{
    [Fact]
    public async Task UnreadableRegistrationRetainsRevokeAndLogsHoldOnlyOncePerWorker()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir, productionBinding: true);
        var stops = 0;
        var cancels = 0;
        var handler = new AgentStateCommandHandler(f.Store, _ => throw new AgentRegistrationChangedException(),
            f.Lifecycle, () => cancels++, f.Log, () => stops++, new AgentRevokeFinalResults(),
            _ => throw new IOException("test-only unreadable registration"));

        await handler.OnResultFinalAsync("agent-a", "c1", default);
        await handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);
        Assert.False(f.Secrets.Cleared);
        Assert.Equal(2, stops);
        Assert.Equal(2, cancels);
        Assert.Single(f.Log.Warnings.Where(line => line.Contains("pending revoke retained:")));
    }

    [Fact]
    public async Task LegacyRevokeRecoveryRequiresCommittedEnrollmentThenAllowsFirstHeartbeatGate()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir, productionBinding: true);
        var stored = f.Store.Load("agent-a");
        var legacyPath = Path.Combine(_dir, "legacy-signed-state.json");
        var legacy = new AgentSignedStateStore(legacyPath);
        Assert.True(legacy.TrySave(stored with { PendingRevoke = stored.PendingRevoke! with { Registration = null } }));
        var before = await f.Lifecycle.LoadAsync(default);
        var nonce = Guid.NewGuid().ToString("N");
        var marker = new AgentEnrollmentMarker("agent.enrollment-promotion.v1", before.Generation,
            "agent-a", "t1", new string('a', 64), nonce, DateTimeOffset.UtcNow.AddMinutes(5));
        Assert.False(AgentEnrollmentPromotion.CompleteLegacyRevoke(marker, before, before, legacy));
        Assert.NotNull(legacy.Load("agent-a").PendingRevoke);
        var adopted = await f.Lifecycle.CompleteEnrollmentAsync(before.Generation, nonce, default);
        Assert.False(AgentEnrollmentPromotion.CompleteLegacyRevoke(marker, before,
            adopted with { LastEnrollmentNonce = Guid.NewGuid().ToString("N") }, legacy));
        Assert.NotNull(legacy.Load("agent-a").PendingRevoke);

        Assert.True(AgentEnrollmentPromotion.CompleteLegacyRevoke(marker, before, adopted, legacy));

        var reloaded = new AgentSignedStateStore(legacyPath);
        Assert.Null(reloaded.Load("agent-a").PendingRevoke);
        var restarted = f.FreshWorker(reloaded, adopted.Generation);
        var replay = new CommandReplayStore(Path.Combine(_dir, CommandReplayStore.FileName));
        var stopped = false;
        var startup = new ServerServiceStartup(() => reloaded.Load("agent-a").PendingRevoke is not null,
            _ => Task.CompletedTask, ct => restarted.RecoverPendingRevokeAsync(replay, ct),
            () => replay.IsAvailable, () => stopped, () => stopped = true, f.Log);
        Assert.True(await startup.RecoverPendingRevokeAsync(default, default));
        Assert.False(stopped);
        Assert.False(f.Secrets.Cleared);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task KeyOrBackendChangeAloneDoesNotDiscardPendingRevoke(bool keyChanged)
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir, productionBinding: true);
        if (keyChanged) f.Secrets.Key = "different-test-key";
        else f.Secrets.Backend = "https://different-backend.invalid";

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);
        Assert.True(f.Store.IsQuarantined("agent-a"));
        Assert.Equal(1, f.Stops);
        Assert.False(f.Secrets.Cleared);
    }

    [Theory]
    [InlineData(AgentLifecycleState.NeedsReenrollment)]
    [InlineData(AgentLifecycleState.BlockedConfig)]
    public async Task SameRegistrationGenerationChangeRetainsRevokeAndStopsNetwork(AgentLifecycleState state)
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir, productionBinding: true);
        var before = await f.LifecycleStore.LoadAsync(default);
        Assert.NotNull(await f.LifecycleStore.TrySaveAsync(before with { State = state, Generation = 1 }, before.Revision, default));

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Equal(state, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);
        Assert.True(f.Store.IsQuarantined("agent-a"));
        Assert.Equal(1, f.Stops);
        Assert.Equal(1, f.Cancels);
        Assert.False(f.Secrets.Cleared);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SameAgentIdWithDifferentTenantOrEnrollmentNonceSkipsOnlyOldRevoke(bool nonceChanged)
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir, productionBinding: true);
        if (nonceChanged)
            await f.Lifecycle.CompleteEnrollmentAsync(0, Guid.NewGuid().ToString("N"), default);
        else
            f.Secrets.Identity = f.Secrets.Identity with { TenantId = "tenant-b" };

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Null(f.Store.Load("agent-a").PendingRevoke);
        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Equal(0, f.Stops);
        Assert.Equal(0, f.Cancels);
        Assert.False(f.Secrets.Cleared);
    }

    [Fact]
    public async Task FreshWorkerAppliesRetainedSameRegistrationRevokeExactlyOnce()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir, productionBinding: true);
        var before = await f.LifecycleStore.LoadAsync(default);
        Assert.NotNull(await f.LifecycleStore.TrySaveAsync(before with { Generation = 1 }, before.Revision, default));
        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);
        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);
        var reloaded = new AgentSignedStateStore(Path.Combine(_dir, AgentSignedStateStore.FileName));
        var restarted = f.FreshWorker(reloaded, 1);
        var replay = new CommandReplayStore(Path.Combine(_dir, CommandReplayStore.FileName));

        await restarted.RecoverPendingRevokeAsync(replay, default);
        await restarted.RecoverPendingRevokeAsync(replay, default);

        Assert.Equal(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Null(reloaded.Load("agent-a").PendingRevoke);
        Assert.Equal(1, f.Secrets.ClearCalls);
    }

    [Fact]
    public async Task LegacyPendingFileWithoutContextRemainsQuarantinedAndIsNotSilentlyDiscarded()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir, productionBinding: true);
        var stored = f.Store.Load("agent-a");
        var legacyPath = Path.Combine(_dir, "legacy-signed-state.json");
        var legacy = new AgentSignedStateStore(legacyPath);
        Assert.True(legacy.TrySave(stored with { PendingRevoke = stored.PendingRevoke! with { Registration = null } }));
        var reloaded = new AgentSignedStateStore(legacyPath);
        var restarted = f.FreshWorker(reloaded, 0);

        await restarted.RecoverPendingRevokeAsync(new CommandReplayStore(Path.Combine(_dir, CommandReplayStore.FileName)), default);

        Assert.NotNull(reloaded.Load("agent-a").PendingRevoke);
        Assert.True(reloaded.IsQuarantined("agent-a"));
        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.False(f.Secrets.Cleared);
        Assert.Equal(1, f.Stops);
    }
}
