using System.Diagnostics;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support evidence: real command verification/replay with a fake update operation and backend.</summary>
public sealed class AgentUpdateTransportIntegrationTests
{
    private static readonly Lazy<TestSigner> SecondarySigner = new(() => new TestSigner(2048));

    [Theory]
    [InlineData(AgentProducts.Cerberus)]
    [InlineData(AgentProducts.Secondary)]
    public async Task SignedUpdate_IsProductBoundAndDuplicateDoesNotExecuteAgain(string product)
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        var primary = TestSigner.Default;
        var secondary = SecondarySigner.Value;
        var anchors = AgentProfileMetadata.ParseProductAnchors(product, Metadata(primary), Metadata(secondary),
            Array.Empty<string>());
        var update = new FakeCommandHandler(EnvelopeTypes.AgentUpdateRequest);
        await using var queue = new EnvelopeExecutionQueue(h.Api, h.Store, new[] { update },
            _ => Task.FromResult(h.AgentId), () => false, h.Time, h.Log);
        queue.Start();
        var processor = new EnvelopeCommandProcessor(h.Api, anchors, queue, EnvelopeTypes.ServerSet, h.Log);
        h.Signer = product == AgentProducts.Cerberus ? primary : secondary;
        var command = h.Cmd(p =>
        {
            p.Type = EnvelopeTypes.AgentUpdateRequest;
            p.PayloadJson = """{"schema_version":"agent.update.request.v1","mode":"install"}""";
        });

        await processor.ProcessAsync(new[] { command }, default);
        await Wait.UntilAsync(() => h.Store.Find(h.AgentId, command.Id)?.ResultSubmitted == true, "update result persisted");
        await processor.ProcessAsync(new[] { command }, default);
        Assert.Equal(1, update.Calls);
        Assert.Equal(EnvelopeRecordStates.Done, h.Store.Find(h.AgentId, command.Id)!.State);

        h.Signer = product == AgentProducts.Cerberus ? secondary : primary;
        var foreign = h.Cmd(p =>
        {
            p.Type = EnvelopeTypes.AgentUpdateRequest;
            p.PayloadJson = """{"schema_version":"agent.update.request.v1","mode":"install"}""";
        });
        await processor.ProcessAsync(new[] { foreign }, default);
        Assert.Equal(1, processor.RejectionCounts[EnvelopeCodes.KeyUnknown]);
        Assert.Null(h.Store.Find(h.AgentId, foreign.Id));
        Assert.Equal(1, update.Calls);
    }

    [Fact]
    public async Task LeaseBoundLegacyUpdate_DuplicateDoesNotExecuteAgain()
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        var update = new FakeCommandHandler(EnvelopeTypes.AgentUpdateRequest);
        var directory = Path.GetDirectoryName(h.StorePath)!;
        var dispatcher = new CommandDispatcher(new[] { update },
            new IdempotencyCache(Path.Combine(directory, "update-idem.json"), 10, TimeSpan.FromHours(1)));
        var store = new CommandReplayStore(Path.Combine(directory, "update-legacy.json"));
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(120), 1),
            store, _ => Task.FromResult(h.AgentId), h.Log, h.Time);
        var command = new AgentCommand("11111111-1111-4111-8111-111111111111", EnvelopeTypes.AgentUpdateRequest,
            "update-1", new { schema_version = "agent.update.request.v1", mode = "check" },
            "33333333-3333-4333-8333-333333333333", null, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300)
        { SafeLeaseDeadlineTimestamp = Stopwatch.GetTimestamp() + 240 * Stopwatch.Frequency };

        await processor.ProcessAsync(new[] { command }, default);
        await Wait.UntilAsync(() => store.Find(h.AgentId, command.Id)?.ResultSubmitted == true, "legacy update result persisted");
        await processor.ProcessAsync(new[] { command }, default);
        Assert.Equal(1, update.Calls);
        Assert.Equal(EnvelopeRecordStates.Done, store.Find(h.AgentId, command.Id)!.State);
    }

    private static string Metadata(TestSigner signer)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(Convert.ToBase64String(signer.Anchor.Spki)));
}
