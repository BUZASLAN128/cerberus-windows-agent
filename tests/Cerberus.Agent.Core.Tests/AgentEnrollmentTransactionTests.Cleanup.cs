using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentEnrollmentTransactionTests
{
    [Fact]
    public async Task CommittedCleanupSurvivesFailedClearAndRestartWithoutASecondEnrollment()
    {
        using var fixture = await Fixture.CreateAsync();
        var before = await fixture.Lifecycle.LoadAsync(default);
        var adopted = await fixture.Lifecycle.CommitEnrollmentAsync(before.Generation, fixture.Nonce,
            ct => fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync,
                ct, "new-agent", AgentProducts.Cerberus), default);
        var cleanup = fixture.Transaction.CleanupStore(AgentProducts.Cerberus);
        Assert.Equal(adopted.Generation, cleanup.Read()!.Generation);
        Assert.False(cleanup.TryComplete(adopted, "new-agent", _ => false));
        using var restarted = fixture.CopyCrashCheckpoint();
        var current = await restarted.Lifecycle.LoadAsync(default);
        var resumed = restarted.Transaction.CleanupStore(AgentProducts.Cerberus);
        var statePath = Path.Combine(restarted.Root, "agent-state.json");
        var state = new AgentSignedStateStore(statePath);
        Assert.True(state.TrySave(new("new-agent", 1, true, "claimed", new("prior-command", "agent_revoked"))));
        var clears = 0;
        bool Clear(string id) { clears++; return state.TryClearLegacyRevokeAfterEnrollment(id, true); }
        Assert.False(resumed.TryComplete(current with { LastEnrollmentNonce = Guid.NewGuid().ToString("N") }, "new-agent", Clear));
        Assert.False(resumed.TryComplete(current with { Generation = current.Generation + 1 }, "new-agent", Clear));
        Assert.False(resumed.TryComplete(current, "different-agent", Clear));
        Assert.False(resumed.TryComplete(current with { State = AgentLifecycleState.NeedsReenrollment }, "new-agent", Clear));
        Assert.Equal(0, clears);
        Assert.True(resumed.TryComplete(current, "new-agent", Clear));
        Assert.Null(new AgentSignedStateStore(statePath).Load("new-agent").PendingRevoke);
        Assert.True(restarted.Transaction.CleanupStore(AgentProducts.Cerberus).Read()!.Completed);
        Assert.True(resumed.TryComplete(current, "new-agent", Clear));
        Assert.Equal(1, clears);
    }

    [Fact]
    public async Task UncommittedPublicationCannotCreateACleanupObligation()
    {
        using var fixture = await Fixture.CreateAsync();
        var before = await fixture.Lifecycle.LoadAsync(default);
        await using (await fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync,
            default, "new-agent", AgentProducts.Cerberus)) { }
        Assert.Null(fixture.Transaction.CleanupStore(AgentProducts.Cerberus).Read());
    }
}
