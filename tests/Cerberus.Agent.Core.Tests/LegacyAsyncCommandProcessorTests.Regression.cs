using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class LegacyAsyncCommandProcessorTests
{
    [Fact]
    public async Task CompletedResultIsSubmittedBeforeNextSlowCommandFinishes()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var first = Command();
        var second = Command() with { Id = Guid.NewGuid().ToString("D"), IdempotencyKey = "second" };
        handler.Body = async (command, ct) =>
        {
            if (command.Id == second.Id)
            {
                handler.Started.TrySetResult();
                await handler.Gate.Task.WaitAsync(ct);
            }
            return FakeCommandHandler.Done();
        };
        var dispatcher = Dispatcher(h, handler);
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            NewStore(h), _ => Task.FromResult(h.AgentId));
        try
        {
            await processor.ProcessAsync(new[] { first, second }, default);
            await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(first.Id, Assert.Single(h.Backend.Results).CommandId);
        }
        finally { handler.Gate.TrySetResult(); }
        await Wait.UntilAsync(() => h.Backend.Results.Count == 2, "second result");
    }

    [Fact]
    public async Task CorruptReplayRequiresVerifiedNewEnrollmentEpochIncludingForTheSameAgentId()
    {
        await using var h = EnvelopeHarness.Create();
        var path = Path.Combine(Path.GetDirectoryName(h.StorePath)!, "legacy-async.v1.json");
        var identity = new AgentIdentity(h.AgentId, "tenant-a");
        var fingerprint = AgentKeyFingerprint.Prefix + new string('a', 64);
        CommandReplayStore Open(AgentIdentity id, AgentLifecycleSnapshot state, string? key = null)
            => CommandReplayStore.OpenLegacyAsyncForEnrollment(id, state, h.Log, path, key ?? fingerprint);
        var lifecycle = new AgentLifecycleSnapshot { Generation = 1, LastEnrollmentNonce = Guid.NewGuid().ToString("N") };
        Assert.True(Open(identity, lifecycle).IsAvailable);
        File.WriteAllText(path, "broken replay");
        var reset = Open(identity, lifecycle);
        Assert.True(reset.ResetAt > 0);
        Assert.True(Open(identity, lifecycle).ResetAt > 0);
        var reenrolled = lifecycle with { Generation = 2, LastEnrollmentNonce = Guid.NewGuid().ToString("N") };
        Assert.True(Open(identity, lifecycle with { Generation = 2 }).ResetAt > 0);
        Assert.False(CommandReplayStore.OpenLegacyAsyncForEnrollment(identity, reenrolled, h.Log, path).IsAvailable);
        Assert.False(Open(identity, reenrolled with { Generation = 1 }).IsAvailable);
        Assert.False(Open(identity, reenrolled with { LastEnrollmentNonce = null }).IsAvailable);
        var prior = File.ReadAllBytes(path);
        var recovered = Open(identity, reenrolled);
        Assert.True(recovered.IsAvailable);
        Assert.Equal(0, recovered.ResetAt);
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = Dispatcher(h, handler);
        Assert.Equal(prior, File.ReadAllBytes(path)); // Prior epoch and its reset are retained.
        // The new epoch cannot authorize a command bound to another registration.
        await using (var wrong = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            recovered, _ => Task.FromResult("different-agent")))
            await wrong.ProcessAsync(new[] { Command() }, default);
        Assert.Equal(0, handler.Calls);
        await using (var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            recovered, _ => Task.FromResult(identity.AgentId)))
        {
            await processor.ProcessAsync(new[] { Command() }, default);
            await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "new enrollment result");
        }
        Assert.Equal(1, handler.Calls);
        Assert.NotNull(Open(identity, reenrolled).Find(identity.AgentId, Command().Id));
        Assert.False(Open(identity, lifecycle).IsAvailable);
        var epochPath = Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!, "legacy-async.v1-enrolled-*.json"));
        File.Delete(epochPath);
        Assert.True(Open(identity, reenrolled).ResetAt > 0);
        Assert.True(Open(identity, reenrolled).ResetAt > 0); // Restart cannot treat loss as first admission.
        var third = reenrolled with { Generation = 3, LastEnrollmentNonce = Guid.NewGuid().ToString("N") };
        Assert.Equal(0, Open(identity, third).ResetAt);
        Assert.Contains(h.Log.Lines, line => line.Contains("verified re-enrollment"));
    }

    [Fact]
    public async Task InvalidBindingCannotFallBackToFreshReplayOrUnsignedWork()
    {
        await using var h = EnvelopeHarness.Create();
        var path = Path.Combine(Path.GetDirectoryName(h.StorePath)!, "legacy-async.v1.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path + ".enrollment", "broken binding");
        var store = CommandReplayStore.OpenLegacyAsyncForEnrollment(new AgentIdentity(h.AgentId, "tenant-a"),
            new AgentLifecycleSnapshot { Generation = 2, LastEnrollmentNonce = Guid.NewGuid().ToString("N") }, h.Log, path);
        Assert.False(store.IsAvailable);
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = Dispatcher(h, handler);
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            store, _ => Task.FromResult(h.AgentId));
        await processor.ProcessAsync(new[] { Command(), Command() with { LeaseId = null } }, default);
        Assert.Equal(0, handler.Calls);
        Assert.Empty(h.Backend.Results);
        Assert.False(File.Exists(path));
    }
}
