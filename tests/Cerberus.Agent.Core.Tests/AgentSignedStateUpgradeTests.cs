using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentSignedStateUpgradeTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "cerberus-state-upgrade-" + Guid.NewGuid().ToString("N"));
    private string StatePath => Path.Combine(_directory, AgentSignedStateStore.FileName);

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Version1006SnapshotPreservesRegistrationQuarantineRevokeAndSequence(bool quarantine, bool revoke)
    {
        WriteLegacySnapshot(quarantine, revoke);
        var store = new AgentSignedStateStore(StatePath, enrolledAgentId: "agent-legacy");
        var state = store.Load("agent-legacy");
        Assert.Equal(9, state.StateSeq);
        Assert.Equal("claimed", state.RegistrationState);
        Assert.Equal(quarantine, state.QuarantineActive);
        Assert.Equal(revoke, state.PendingRevoke is not null);
        Assert.Equal(quarantine || revoke, store.IsQuarantined());
        Assert.Null(state.LastAppliedCommandId); // Field was absent in 1006, not corrupt.
        Assert.False(store.RequiresRecovery);
        Assert.False(store.TrySave(new("agent-legacy", 9, false, "claimed")));
    }

    [Fact]
    public void Version1006RegistrationWithoutSnapshotEntersVisibleFailClosedRecoveryOnUpgrade()
    {
        // 1006 e2631f79 allowed an enrolled registration with no agent_state snapshot.
        // It supplied no enrolledAgentId to this store. Credentials alone cannot prove signed state.
        var legacy = new AgentSignedStateStore(StatePath);
        Assert.Equal(0, legacy.Load("agent-legacy").StateSeq);
        Assert.False(File.Exists(StatePath));
        var log = new RecordingLogger();
        var upgraded = new AgentSignedStateStore(StatePath, log, enrolledAgentId: "agent-legacy");
        Assert.True(upgraded.RequiresRecovery);
        Assert.True(upgraded.IsQuarantined());
        using var marker = JsonDocument.Parse(File.ReadAllBytes(StatePath));
        var state = marker.RootElement.GetProperty("state");
        Assert.Equal("unreadable", state.GetProperty("reset").GetString());
        Assert.Equal(0, state.GetProperty("state_seq").GetInt64());
        Assert.Equal(JsonValueKind.Null, state.GetProperty("registration_state").ValueKind);
        Assert.Contains(log.Lines, line => line.StartsWith("WARN ") && line.Contains("snapshot missing"));
        Assert.True(new AgentSignedStateStore(StatePath, enrolledAgentId: "agent-legacy").RequiresRecovery);
    }

    [Fact]
    public void LegacySnapshotBelowProtectedSequenceFloorCannotReopenCommands()
    {
        WriteLegacySnapshot(false, false);
        File.WriteAllText(StatePath + ".seq", """{"schema":"cerberus.agent-state-seq.v1","agent_id":"agent-legacy","state_seq":10}""");
        var upgraded = new AgentSignedStateStore(StatePath, enrolledAgentId: "agent-legacy");
        Assert.True(upgraded.RequiresRecovery);
        Assert.True(upgraded.IsQuarantined());
        Assert.Equal(10, upgraded.RecoveryFloor);
        Assert.False(upgraded.TrySave(new("agent-legacy", 9, false, "claimed")));
    }

    private void WriteLegacySnapshot(bool quarantine, bool revoke)
    {
        Directory.CreateDirectory(_directory);
        // Literal persisted schema from e2631f79; no new DTO is used to manufacture the old file.
        var pending = revoke ? ",\"pending_revoke\":{\"command_id\":\"legacy-revoke\",\"reason_code\":\"agent_revoked\"}" : "";
        File.WriteAllText(StatePath, "{\"schema\":\"cerberus.agent-state.v1\",\"state\":{\"agent_id\":\"agent-legacy\",\"state_seq\":9,\"quarantine_active\":" +
            (quarantine ? "true" : "false") + ",\"registration_state\":\"claimed\"" + pending + "}}");
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory)) Directory.Delete(_directory, true);
    }
}
