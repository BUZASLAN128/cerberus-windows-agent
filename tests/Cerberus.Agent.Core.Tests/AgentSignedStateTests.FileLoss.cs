using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentSignedStateTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LostStateRemainsResetAcrossRestartAndOnlyNewerStateOpensIt(bool pendingRevoke)
    {
        var store = new AgentSignedStateStore(StatePath, enrolledAgentId: "agent-a");
        Assert.True(store.RequiresRecovery);
        Assert.True(store.TrySave(new("agent-a", 7, true, "claimed",
            pendingRevoke ? new("revoke-command", Revoked) : null)));
        File.Delete(StatePath);
        var recovered = new AgentSignedStateStore(StatePath, enrolledAgentId: "agent-a");
        Assert.True(recovered.RequiresRecovery);
        Assert.True(recovered.HoldsNormalWork());
        Assert.Equal(7, recovered.RecoveryFloor);
        var restarted = new AgentSignedStateStore(StatePath, enrolledAgentId: "agent-a");
        Assert.True(restarted.RequiresRecovery);
        Assert.Equal(7, restarted.RecoveryFloor);
        Assert.False(restarted.TrySave(new("agent-a", 7, false, "claimed")));
        restarted.SetRecoverySourceSupported(false);
        Assert.False(restarted.HoldsNormalWork());
        Assert.True(restarted.IsQuarantined()); // Signed business commands remain closed without a source.
        Assert.True(restarted.TrySave(new("agent-a", 8, false, "claimed")));
        Assert.False(restarted.RequiresRecovery);
        Assert.False(restarted.IsQuarantined());
    }

    [Fact]
    public void RolledBackStateCannotHideTheDurableHighWaterQuarantine()
    {
        var store = new AgentSignedStateStore(StatePath);
        Assert.True(store.TrySave(new("agent-a", 1, false, "claimed")));
        var old = File.ReadAllBytes(StatePath);
        Assert.True(store.TrySave(new("agent-a", 9, true, "claimed")));
        File.WriteAllBytes(StatePath, old);
        var recovered = new AgentSignedStateStore(StatePath);
        Assert.True(recovered.RequiresRecovery);
        Assert.Equal(9, recovered.RecoveryFloor);
        Assert.False(recovered.TrySave(new("agent-a", 8, false, "claimed")));
    }

    [Fact]
    public void EnrolledMissingReplayFilePersistsResetBeforeAnyReservation()
    {
        var path = Path.Combine(_dir, CommandReplayStore.FileName);
        var clock = new FakeTime(EnvelopeHarness.T0);
        var store = new CommandReplayStore(path, clock, enrollmentEstablished: true);
        Assert.True(store.IsAvailable);
        Assert.Equal(EnvelopeHarness.T0, store.ResetAt);
        Assert.True(File.Exists(path));
        Assert.Equal(store.ResetAt, new CommandReplayStore(path, clock, enrollmentEstablished: true).ResetAt);
    }
}
