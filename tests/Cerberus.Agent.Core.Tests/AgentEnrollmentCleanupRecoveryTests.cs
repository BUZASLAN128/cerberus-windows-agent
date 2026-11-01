using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentEnrollmentCleanupRecoveryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompletedReceiptWithUnavailableCredentialsRetainsEvidenceAndLetsStartupContinue(bool undecryptable)
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var nonce = Guid.NewGuid().ToString("N");
            var snapshot = new AgentLifecycleSnapshot { Generation = 1, LastEnrollmentNonce = nonce };
            var lifecycle = new InMemoryAgentLifecycleStateStore(snapshot);
            var cleanup = new AgentEnrollmentRevokeCleanupStore(Path.Combine(root, "cleanup.json"));
            Assert.True(cleanup.RecordCommitted(new(1, nonce, "agent-a", AgentProducts.Cerberus)));
            Assert.True(cleanup.TryComplete(snapshot, "agent-a", _ => true));
            var receipt = cleanup.Read();
            Assert.True(receipt!.Completed);
            var state = new AgentSignedStateStore(Path.Combine(root, "state.json"));
            var pending = new AgentPendingRevoke("later-revoke", "agent_revoked", new("agent-a", "tenant", nonce));
            Assert.True(state.TrySave(new("agent-a", 1, true, "claimed", pending)));
            Exception failure = undecryptable ? new System.Security.Cryptography.CryptographicException("Owned unreadable fixture")
                : new FileNotFoundException("Owned missing fixture");
            var stateReads = 0;

            var result = await AgentEnrollmentCleanupRecovery.UnderFenceAsync(lifecycle, new UnavailableSecrets(failure), default,
                _ => cleanup, _ => { stateReads++; return state; });

            Assert.False(result);
            Assert.Equal(receipt, cleanup.Read());
            Assert.Equal(snapshot, await lifecycle.LoadAsync(default));
            Assert.Equal(pending, state.Load("agent-a").PendingRevoke);
            Assert.Equal(0, stateReads);
        }
        finally { Directory.Delete(root, true); }
    }

    private sealed class UnavailableSecrets(Exception failure) : ISecretStore
    {
        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl,
            string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct) => throw failure;
        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct) => throw new NotSupportedException();
        public Task ClearAsync(CancellationToken ct) => throw new NotSupportedException();
    }
}
