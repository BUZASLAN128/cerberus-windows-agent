using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateStateBarrierTests
{
    [Theory]
    [InlineData("revoke")]
    [InlineData("missing_replay")]
    [InlineData("corrupt_replay")]
    [InlineData("signed_recovery")]
    public Task StagedLaunchIsDeniedUnderRealFenceWithoutRepairingEvidence(string failure) => AssertBarrier(failure, true);

    [Theory]
    [InlineData("revoke")]
    [InlineData("missing_replay")]
    [InlineData("corrupt_replay")]
    [InlineData("signed_recovery")]
    [InlineData("corrupt_signed_state")]
    public Task ReadOnlyStateProbeBlocksWithoutRepairingEvidence(string failure) => AssertBarrier(failure, false);

    private static async Task AssertBarrier(string failure, bool realFence)
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-launch-barrier-" + Guid.NewGuid().ToString("N"));
        try
        {
            if (realFence) AgentUpdateSecurity.EnsureProtectedRoot(root);
            else Directory.CreateDirectory(root);
            var replayPath = Path.Combine(root, "replay.json");
            var statePath = Path.Combine(root, "state.json");
            var snapshot = new AgentLifecycleSnapshot { Generation = 1, LastEnrollmentNonce = Guid.NewGuid().ToString("N") };
            var pending = failure is "revoke" or "corrupt_replay" ? new AgentPendingRevoke("owned-revoke", "agent_revoked",
                new("agent-a", "t1", snapshot.LastEnrollmentNonce)) : null;
            Assert.True(new AgentStateHighWater(statePath, NullAgentLogger.Instance, false).TryWrite("agent-a", 1));
            if (failure != "missing_replay")
                File.WriteAllText(statePath, System.Text.Json.JsonSerializer.Serialize(new
                {
                    schema = "cerberus.agent-state.v1",
                    state = new AgentSignedState("agent-a", 1, false, null, pending,
                        Reset: failure == "signed_recovery" ? AgentSignedState.ResetUnreadable : null),
                }));
            if (failure == "corrupt_signed_state") File.WriteAllText(statePath, "{owned malformed state");
            if (failure == "corrupt_replay") File.WriteAllText(replayPath, "{owned malformed replay");
            else if (failure != "missing_replay") StoreFileWriter.Write(replayPath, 0, Array.Empty<CommandReplayRecord>());
            var stateBytes = File.Exists(statePath) ? File.ReadAllBytes(statePath) : null;
            var highWaterBytes = File.ReadAllBytes(statePath + AgentStateHighWater.Suffix);
            var replayBytes = File.Exists(replayPath) ? File.ReadAllBytes(replayPath) : null;
            var active = new AgentUpdateJournal { AttemptId = "owned-attempt", Phase = AgentUpdateStates.Staged,
                LifecycleGeneration = snapshot.Generation };
            var launches = 0;

            bool Pending(AgentLifecycleSnapshot current) => AgentUpdateLocalService.PendingStateDelivery(current,
                new Secrets(), _ => new CommandReplayStore(replayPath), _ => new AgentSignedStateStore(statePath));
            if (realFence)
                await Assert.ThrowsAsync<InvalidOperationException>(() => AgentUpdateLocalService.LaunchUnderFenceAsync(
                    active, true, _ => Task.FromResult(snapshot), Pending, _ => launches++, default, root));
            else Assert.True(Pending(snapshot));

            Assert.Equal(0, launches);
            if (stateBytes is null) Assert.False(File.Exists(statePath));
            else Assert.Equal(stateBytes, File.ReadAllBytes(statePath));
            Assert.Equal(highWaterBytes, File.ReadAllBytes(statePath + AgentStateHighWater.Suffix));
            if (replayBytes is null) Assert.False(File.Exists(replayPath));
            else Assert.Equal(replayBytes, File.ReadAllBytes(replayPath));
            Assert.Empty(Directory.GetFiles(root, "*.corrupt-*"));
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
        }
    }

    [Fact]
    public void NormalEnrollmentReplayResetAndNewSnapshotResetAreNotUpdateBarriers()
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-normal-update-probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var replayPath = Path.Combine(root, "replay.json");
            var statePath = Path.Combine(root, "state.json");
            var replay = new CommandReplayStore(replayPath, enrollmentEstablished: true);
            Assert.True(replay.IsAvailable); // Real first-enrollment initialization writes reset_at.
            Assert.True(replay.ResetAt > 0);
            bool Pending() => AgentUpdateLocalService.PendingStateDelivery(new() { Generation = 1 }, new Secrets(),
                _ => new CommandReplayStore(replayPath), _ => new AgentSignedStateStore(statePath));
            Assert.False(Pending());
            var state = new AgentSignedStateStore(statePath, enrolledAgentId: "agent-a");
            Assert.True(state.RequiresRecovery); // Real missing-snapshot initialization writes Reset.
            Assert.True(File.Exists(statePath));
            Assert.False(Pending());
            Assert.True(state.RequiresRecovery); // Runtime holds remain independent and unchanged.
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
        }
    }

    [Theory]
    [InlineData("current", "missing", true)]
    [InlineData("current", "reset", true)]
    [InlineData("current", "settled", false)]
    [InlineData("other", "missing", false)]
    [InlineData("other", "reset", false)]
    [InlineData("none", "missing", false)]
    [InlineData("none", "reset", false)]
    [InlineData("zero", "reset", false)]
    [InlineData("corrupt", "missing", true)]
    [InlineData("corrupt", "settled", true)]
    public void SnapshotLossBlocksOnlyKnownBaselineAndUnreadableSidecar(string baseline, string snapshot, bool blocked)
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-baseline-update-probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var replayPath = Path.Combine(root, "replay.json");
            var statePath = Path.Combine(root, "state.json");
            if (baseline == "corrupt") File.WriteAllText(statePath + AgentStateHighWater.Suffix, "{owned malformed sidecar");
            else if (baseline != "none")
                Assert.True(new AgentStateHighWater(statePath, NullAgentLogger.Instance, false)
                    .TryWrite(baseline == "other" ? "other-agent" : "agent-a", baseline == "zero" ? 0 : 1));
            if (snapshot != "missing")
                File.WriteAllText(statePath, System.Text.Json.JsonSerializer.Serialize(new
                {
                    schema = "cerberus.agent-state.v1",
                    state = new AgentSignedState("agent-a", baseline == "none" || baseline == "zero" ? 0 : 1,
                        false, null, Reset: snapshot == "reset" ? AgentSignedState.ResetUnreadable : null),
                }));
            var before = Directory.GetFiles(root).ToDictionary(path => path, File.ReadAllBytes);

            Assert.Equal(blocked, AgentUpdateLocalService.PendingStateDelivery(new() { Generation = 1 }, new Secrets(),
                _ => new CommandReplayStore(replayPath), _ => new AgentSignedStateStore(statePath)));

            Assert.Equal(before.Keys.Order(), Directory.GetFiles(root).Order());
            foreach (var file in before) Assert.Equal(file.Value, File.ReadAllBytes(file.Key));
            Assert.False(File.Exists(replayPath));
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
        }
    }

    [Theory]
    [InlineData("{owned malformed replay")]
    [InlineData("")]
    [InlineData("{\"schema\":\"unsupported\",\"reset_at\":0,\"records\":[]}")]
    public void CorruptReplayWithoutSnapshotBlocksUntilWorkerRepairsIt(string damagedReplay)
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-corrupt-update-probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var replayPath = Path.Combine(root, "replay.json");
            var statePath = Path.Combine(root, "state.json");
            File.WriteAllText(replayPath, damagedReplay);
            var original = File.ReadAllBytes(replayPath);
            bool Pending() => AgentUpdateLocalService.PendingStateDelivery(new() { Generation = 1 }, new Secrets(),
                _ => new CommandReplayStore(replayPath), _ => new AgentSignedStateStore(statePath));

            Assert.True(Pending());
            Assert.Equal(original, File.ReadAllBytes(replayPath));
            Assert.False(File.Exists(statePath));
            Assert.Empty(Directory.GetFiles(root, "*.corrupt-*"));

            var workerReplay = new CommandReplayStore(replayPath, enrollmentEstablished: true);
            Assert.True(workerReplay.IsAvailable);
            Assert.True(workerReplay.ResetAt > 0);
            var retained = Assert.Single(Directory.GetFiles(root, "*.corrupt-*"));
            Assert.Equal(original, File.ReadAllBytes(retained));
            var repaired = File.ReadAllBytes(replayPath);
            Assert.False(Pending());
            Assert.Equal(repaired, File.ReadAllBytes(replayPath));
            Assert.False(File.Exists(statePath));
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExistingUnreadableOrNonFileReplayBlocksWithoutRepair(bool unreadable)
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-unreadable-update-probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var replayPath = Path.Combine(root, "replay.json");
            var statePath = Path.Combine(root, "state.json");
            if (unreadable) StoreFileWriter.Write(replayPath, 0, Array.Empty<CommandReplayRecord>());
            else Directory.CreateDirectory(replayPath);
            using var locked = unreadable ? new FileStream(replayPath, FileMode.Open, FileAccess.Read, FileShare.None) : null;

            Assert.True(AgentUpdateLocalService.PendingStateDelivery(new() { Generation = 1 }, new Secrets(),
                _ => new CommandReplayStore(replayPath), _ => new AgentSignedStateStore(statePath)));
            Assert.False(File.Exists(statePath));
            Assert.Empty(Directory.GetFiles(root, "*.corrupt-*"));
            if (unreadable) Assert.True(File.Exists(replayPath));
            else Assert.True(Directory.Exists(replayPath));
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
        }
    }

    [Fact]
    public void MissingReplayAloneIsNotAnUpdateBarrier()
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-missing-update-probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            Assert.False(AgentUpdateLocalService.PendingStateDelivery(new() { Generation = 1 }, new Secrets(),
                _ => new CommandReplayStore(Path.Combine(root, "replay.json")),
                _ => new AgentSignedStateStore(Path.Combine(root, "state.json"))));
            Assert.Empty(Directory.GetFiles(root));
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
        }
    }

    [Fact]
    public async Task UnauthorizedFenceCallCannotReachStateProbeOrLaunch()
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-untrusted-fence-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var directory = new DirectoryInfo(root);
            var acl = System.IO.FileSystemAclExtensions.GetAccessControl(directory);
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.AuthenticatedUserSid, null),
                System.Security.AccessControl.FileSystemRights.Modify,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
            System.IO.FileSystemAclExtensions.SetAccessControl(directory, acl);
            var probes = 0;
            var launches = 0;
            var denied = await Assert.ThrowsAsync<InvalidOperationException>(() => AgentUpdateLocalService.LaunchUnderFenceAsync(
                new() { Phase = AgentUpdateStates.Staged }, true, _ => { probes++; return Task.FromResult(new AgentLifecycleSnapshot()); },
                _ => false, _ => launches++, default, root));
            Assert.StartsWith("Protected update object", denied.Message);
            Assert.Equal(0, probes);
            Assert.Equal(0, launches);
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
        }
    }

    [Theory]
    [InlineData(AgentProducts.Cerberus)]
    [InlineData(AgentProducts.Secondary)]
    public void SettledCurrentProductDoesNotRequireTheOtherProductsReplayStore(string product)
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-settled-probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var replay = Path.Combine(root, "replay.json");
            var state = Path.Combine(root, "state.json");
            StoreFileWriter.Write(replay, 0, Array.Empty<CommandReplayRecord>());
            Assert.True(new AgentSignedStateStore(state).TrySave(new("agent-a", 1, false, null)));
            var products = new List<string>();
            Assert.False(AgentUpdateLocalService.PendingStateDelivery(new() { Generation = 1 }, new Secrets(product),
                requested => { products.Add(requested); return new CommandReplayStore(replay); },
                requested => { products.Add(requested); return new AgentSignedStateStore(state); }));
            Assert.Equal(new[] { product, product }, products);
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
        }
    }

    private sealed class Secrets(string product = AgentProducts.Cerberus) : ISecretStore
    {
        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl,
            string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((new AgentIdentity("agent-a", "t1", product), "owned", "owned", "https://backend.test", (string?)null, (string?)null));
        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct) => throw new NotSupportedException();
        public Task ClearAsync(CancellationToken ct) => throw new NotSupportedException();
    }
}
