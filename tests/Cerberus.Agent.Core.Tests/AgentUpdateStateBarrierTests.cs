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
            var pending = failure == "revoke" ? new AgentPendingRevoke("owned-revoke", "agent_revoked",
                new("agent-a", "t1", snapshot.LastEnrollmentNonce)) : null;
            Assert.True(new AgentSignedStateStore(statePath).TrySave(new("agent-a", 1, false, null, pending)));
            if (failure == "signed_recovery") File.WriteAllText(statePath, "{owned malformed state");
            if (failure == "corrupt_replay") File.WriteAllText(replayPath, "{owned malformed replay");
            else if (failure != "missing_replay") StoreFileWriter.Write(replayPath, 0, Array.Empty<CommandReplayRecord>());
            var stateBytes = File.ReadAllBytes(statePath);
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
            Assert.Equal(stateBytes, File.ReadAllBytes(statePath));
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
            Assert.Contains("untrusted ownership or permissions", denied.Message);
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
