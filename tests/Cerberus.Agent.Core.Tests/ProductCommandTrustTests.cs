using Cerberus.Agent.Core;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed class ProductCommandTrustTests
{
    [Fact]
    public void TrustIsSelectedByProductAndSharedKeyIsRejectedForBoth()
    {
        var anchor = File.ReadAllText(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "tests", "fixtures", "agent-command-test-anchors.b64")).Trim();
        Assert.Single(AgentProfileMetadata.ParseProductAnchors(AgentProducts.Cerberus, anchor, null, Array.Empty<string>()));
        Assert.Single(AgentProfileMetadata.ParseProductAnchors(AgentProducts.Secondary, null, anchor, Array.Empty<string>()));
        Assert.Empty(AgentProfileMetadata.ParseProductAnchors(AgentProducts.Cerberus, anchor, anchor, Array.Empty<string>()));
        Assert.Empty(AgentProfileMetadata.ParseProductAnchors(AgentProducts.Secondary, anchor, anchor, Array.Empty<string>()));
        Assert.Empty(AgentProfileMetadata.ParseProductAnchors("unknown", anchor, null, Array.Empty<string>()));
    }

    [Fact]
    public void ReplayAndSignedStatePathsAreSeparatedByProduct()
    {
        Assert.NotEqual(CommandReplayStore.DefaultPathForProduct(AgentProducts.Cerberus),
            CommandReplayStore.DefaultPathForProduct(AgentProducts.Secondary));
        Assert.NotEqual(AgentSignedStateStore.DefaultPathForProduct(AgentProducts.Cerberus),
            AgentSignedStateStore.DefaultPathForProduct(AgentProducts.Secondary));
        Assert.Throws<InvalidOperationException>(() => CommandReplayStore.DefaultPathForProduct("unknown"));
        Assert.Throws<InvalidOperationException>(() => AgentSignedStateStore.DefaultPathForProduct("unknown"));
    }

    [Fact]
    public void BackendHandlerNeverAutomaticallyRedirectsCredentials()
    {
        using var handler = BackendTrust.CreateHandler();
        Assert.False(handler.AllowAutoRedirect);
    }

    [Fact]
    public async Task RunningWorkerRejectsChangedProductIdentityOrDestination()
    {
        var identity = new AgentIdentity("agent", "tenant", AgentProducts.Secondary);
        var inner = new MutableStore(identity, "https://collector.example");
        var bound = new ProductBoundSecretStore(inner, identity, "https://collector.example");
        Assert.Equal(identity, (await bound.LoadAsync(default)).Identity);
        inner.Identity = identity with { Product = AgentProducts.Cerberus };
        await Assert.ThrowsAsync<AgentRegistrationChangedException>(() => bound.LoadAsync(default));
        await Assert.ThrowsAsync<AgentRegistrationChangedException>(() => bound.ClearAsync(default));
        Assert.False(inner.Cleared);
        inner.Identity = identity;
        inner.Backend = "https://other.example";
        await Assert.ThrowsAsync<AgentRegistrationChangedException>(() => bound.LoadAsync(default));
        await Assert.ThrowsAsync<AgentRegistrationChangedException>(() => bound.SaveAsync(identity, "t", "k", "https://collector.example", null, null, default));
    }

    [Fact]
    public async Task RunningWorkerRejectsNewKeyForTheSameIdentity()
    {
        var identity = new AgentIdentity("agent", "tenant", AgentProducts.Cerberus);
        var inner = new MutableStore(identity, "https://collector.example");
        var bound = new ProductBoundSecretStore(inner, identity, "https://collector.example", "fixture-key");
        Assert.Equal(identity, (await bound.LoadAsync(default)).Identity);
        inner.PrivateKey = "another-fixture-key";
        await Assert.ThrowsAsync<AgentRegistrationChangedException>(() => bound.LoadAsync(default));
        await Assert.ThrowsAsync<AgentRegistrationChangedException>(() => bound.ClearAsync(default));
        Assert.False(inner.Cleared);
    }

    [Fact]
    public async Task PrimaryBackendMigrationCannotRewriteSecondaryRegistration()
    {
        var identity = new AgentIdentity("agent", "tenant", AgentProducts.Secondary);
        var store = new MutableStore(identity, "https://collector.example");
        var current = await store.LoadAsync(default);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            ServerBackendMigration.MigrateAsync(store, current, "https://other.example", default));
        Assert.Equal(0, store.Saves);
        Assert.Equal("https://collector.example", (await store.LoadAsync(default)).Item4);
    }

    [Fact]
    public async Task SecondaryAdapterNeverExecutesAnUnsignedCommand()
    {
        await using var harness = EnvelopeHarness.Create();
        var cache = new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"), "idem.json"), 10, TimeSpan.FromMinutes(5));
        var dispatcher = new CommandDispatcher(new[] { harness.Ping }, cache);
        var processor = EnvelopeWiring.CreateProcessor(harness.Api, harness.Queue, dispatcher, harness.Log, AgentProducts.Secondary);
        await processor.ProcessAsync(new[] { new AgentCommand("unsigned-id", "ping", "idempotency", new { }) }, default);
        Assert.Equal(0, harness.Ping.Calls);
        Assert.Empty(harness.Backend.Requests);
    }

    [Fact]
    public void SecondaryCredentialProbeUsesFiveFieldResponseWithoutClaimAssertion()
    {
        var response = new HeartbeatResponse(Array.Empty<AgentCommand>(), 30, 1, null, 0, 300,
            null, null, null, false, null, null, null, false, null, null, null, null, null);
        Assert.True(AgentLocalControlService.AcceptsCredentialProbe(response, AgentProducts.Secondary));
#if !CERBERUS_SERVER_PROFILE
        Assert.False(AgentLocalControlService.AcceptsCredentialProbe(response, AgentProducts.Cerberus));
#endif
        var wire = System.Text.Json.JsonSerializer.Serialize(AgentLocalControlService.CreateManualHeartbeat(signedOnly: true));
        Assert.Contains(CommandEnvelope.SignedOnlyCapability, wire);
    }

    [Fact]
    public void EnrollmentMarkerBindsSecondaryProductAndBackend()
    {
        var identity = new AgentIdentity("agent", "tenant", AgentProducts.Secondary);
        var marker = new AgentEnrollmentMarker("v1", 0, "agent", "tenant", "digest", "nonce", DateTimeOffset.UtcNow,
            AgentProducts.Secondary, "https://collector.example");
        Assert.True(AgentEnrollmentPromotion.MatchesProduct(marker, identity, "https://collector.example/"));
        Assert.False(AgentEnrollmentPromotion.MatchesProduct(marker, identity, "https://other.example"));
        Assert.False(AgentEnrollmentPromotion.MatchesProduct(marker, identity with { Product = AgentProducts.Cerberus }, "https://collector.example"));
        Assert.False(AgentEnrollmentPromotion.MatchesProduct(marker with { Product = null, BackendUrl = null }, identity, "https://collector.example"));
    }

    private sealed class MutableStore(AgentIdentity identity, string backend) : ISecretStore
    {
        public AgentIdentity Identity = identity;
        public string Backend = backend;
        public bool Cleared;
        public int Saves;
        public string PrivateKey = "fixture-key";
        public Task<(AgentIdentity, string, string, string, string?, string?)> LoadAsync(CancellationToken ct)
            => Task.FromResult<(AgentIdentity, string, string, string, string?, string?)>((Identity, "t", PrivateKey, Backend, null, null));
        public Task SaveAsync(AgentIdentity id, string token, string key, string url, string? ts, string? auth, CancellationToken ct)
        {
            Saves++;
            Identity = id;
            Backend = url;
            return Task.CompletedTask;
        }
        public Task ClearAsync(CancellationToken ct) { Cleared = true; return Task.CompletedTask; }
    }
}
