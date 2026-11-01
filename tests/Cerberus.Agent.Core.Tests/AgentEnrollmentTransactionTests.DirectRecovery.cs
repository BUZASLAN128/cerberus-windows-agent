using System.Text.Json.Nodes;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentEnrollmentTransactionTests
{
    [Theory]
    [InlineData("matching")]
    [InlineData("wrong-nonce")]
    [InlineData("wrong-agent")]
    [InlineData("reset")]
    [InlineData("bound-revoke")]
    public async Task VerifiedDirectPublicationResumesOnlyItsDurableCleanup(string condition)
    {
        using var fixture = await Fixture.CreateAsync();
        var before = await fixture.Lifecycle.LoadAsync(default);
        var marker = new AgentEnrollmentMarker("agent.enrollment-promotion.v1", before.Generation,
            "new-agent", "tenant", new string('a', 64), fixture.Nonce, DateTimeOffset.UtcNow.AddMinutes(5));
        Fixture? crash = null;
        try
        {
            await AgentEnrollmentPromotion.CommitVerifiedAsync(fixture.Lifecycle, marker, default,
                async (generation, nonce, agentId, product, ct) => new CheckpointLease(
                    await fixture.Transaction.BeginLockedAsync(generation, nonce, fixture.Lifecycle.LoadAsync, ct, agentId, product),
                    () => crash = fixture.CopyCrashCheckpoint()));
            Assert.NotNull(crash);
            var adopted = await crash.Lifecycle.LoadAsync(default);
            await crash.Transaction.RecoverWithLockAsync(adopted, default);
            var cleanup = crash.Transaction.CleanupStore(AgentProducts.Cerberus);
            Assert.Equal("new-agent", cleanup.Read()!.AgentId);
            var statePath = Path.Combine(crash.Root, "signed-state.json");
            var state = new AgentSignedStateStore(statePath);
            var registration = condition == "bound-revoke"
                ? new AgentRevokeRegistration("new-agent", "tenant", fixture.Nonce) : null;
            Assert.True(state.TrySave(new("new-agent", 1, true, "claimed", new("prior-revoke", "agent_revoked", registration))));
            if (condition == "reset") await File.WriteAllTextAsync(statePath, "{unreadable owned fixture");
            if (condition == "wrong-agent")
                await crash.Active.SaveAsync(new("other-agent", "tenant"), "owned", "owned", "https://backend.invalid", null, null, default);
            IAgentLifecycleStateStore lifecycle = condition == "wrong-nonce"
                ? new InMemoryAgentLifecycleStateStore(adopted with { LastEnrollmentNonce = Guid.NewGuid().ToString("N") })
                : crash.Lifecycle;
            var current = await lifecycle.LoadAsync(default);
            var cipher = await File.ReadAllBytesAsync(crash.ActivePath);

            var complete = await AgentEnrollmentCleanupRecovery.UnderFenceAsync(lifecycle, crash.Active, default,
                _ => cleanup, _ => new AgentSignedStateStore(statePath));

            var allowed = condition is "matching" or "bound-revoke";
            Assert.Equal(allowed, complete == true);
            Assert.Equal(allowed, cleanup.Read()!.Completed);
            var restarted = new AgentSignedStateStore(statePath);
            if (condition == "matching") Assert.Null(restarted.Load("new-agent").PendingRevoke);
            else if (condition == "reset") Assert.True(restarted.RequiresRecovery);
            else Assert.NotNull(restarted.Load("new-agent").PendingRevoke);
            if (condition == "bound-revoke")
                Assert.Equal(registration, restarted.Load("new-agent").PendingRevoke!.Registration);
            Assert.Equal(current, await lifecycle.LoadAsync(default));
            Assert.Equal(cipher, await File.ReadAllBytesAsync(crash.ActivePath));
        }
        finally { crash?.Dispose(); }
    }

    [Fact]
    public async Task CommittedOldJournalWithoutIdentityHoldsForOperatorWithoutInferringMarkerIdentity()
    {
        using var fixture = await Fixture.CreateAsync();
        var before = await fixture.Lifecycle.LoadAsync(default);
        Fixture? crash = null;
        try
        {
            await fixture.Lifecycle.CommitEnrollmentAsync(before.Generation, fixture.Nonce, async ct =>
                new CheckpointLease(await fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce,
                    fixture.Lifecycle.LoadAsync, ct, "new-agent", AgentProducts.Cerberus),
                    () => crash = fixture.CopyCrashCheckpoint()), default);
            Assert.NotNull(crash);
            var journal = JsonNode.Parse(await File.ReadAllTextAsync(crash.JournalPath))!.AsObject();
            Assert.True(journal.Remove("legacyRevokeAgentId"));
            Assert.True(journal.Remove("legacyRevokeProduct"));
            await File.WriteAllTextAsync(crash.JournalPath, journal.ToJsonString());
            var cipher = await File.ReadAllBytesAsync(crash.ActivePath);
            var current = await crash.Lifecycle.LoadAsync(default);

            var error = await Assert.ThrowsAsync<InvalidDataException>(() => crash.Transaction.RecoverWithLockAsync(current, default));

            Assert.Contains("operator recovery", error.Message);
            Assert.True(File.Exists(crash.JournalPath));
            Assert.True(File.Exists(Path.Combine(crash.DirectoryPath, "enrollment-adoption.json")));
            Assert.True(File.Exists(crash.PendingPath));
            Assert.Null(crash.Transaction.CleanupStore(AgentProducts.Cerberus).Read());
            Assert.Equal(cipher, await File.ReadAllBytesAsync(crash.ActivePath));
            Assert.Equal(current, await crash.Lifecycle.LoadAsync(default));
            await Assert.ThrowsAsync<InvalidOperationException>(() => crash.Transaction.AcquireResolvedAccessAsync(default));
        }
        finally { crash?.Dispose(); }
    }
}
