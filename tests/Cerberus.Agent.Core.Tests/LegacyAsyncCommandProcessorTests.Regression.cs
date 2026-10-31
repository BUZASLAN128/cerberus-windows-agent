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
    public async Task CorruptReplayRequiresVerifiedNewEnrollmentAndNewAgentIdentity()
    {
        await using var h = EnvelopeHarness.Create();
        var path = Path.Combine(Path.GetDirectoryName(h.StorePath)!, "legacy-async.v1.json");
        var identity = new AgentIdentity("old-agent", "tenant-a");
        var lifecycle = new AgentLifecycleSnapshot { Generation = 1, LastEnrollmentNonce = Guid.NewGuid().ToString("N") };
        Assert.True(CommandReplayStore.OpenLegacyAsyncForEnrollment(identity, lifecycle, h.Log, path).IsAvailable);
        File.WriteAllText(path, "broken replay");
        var reset = CommandReplayStore.OpenLegacyAsyncForEnrollment(identity, lifecycle, h.Log, path);
        Assert.True(reset.ResetAt > 0);
        Assert.True(CommandReplayStore.OpenLegacyAsyncForEnrollment(identity, lifecycle, h.Log, path).ResetAt > 0);
        var reenrolled = lifecycle with { Generation = 2, LastEnrollmentNonce = Guid.NewGuid().ToString("N") };
        Assert.True(CommandReplayStore.OpenLegacyAsyncForEnrollment(identity, reenrolled, h.Log, path).ResetAt > 0);
        var next = identity with { AgentId = h.AgentId };
        Assert.False(CommandReplayStore.OpenLegacyAsyncForEnrollment(next, lifecycle, h.Log, path).IsAvailable);
        Assert.False(CommandReplayStore.OpenLegacyAsyncForEnrollment(next, lifecycle with { Generation = 2 }, h.Log, path).IsAvailable);
        Assert.False(CommandReplayStore.OpenLegacyAsyncForEnrollment(next, reenrolled with { LastEnrollmentNonce = null }, h.Log, path).IsAvailable);
        var recovered = CommandReplayStore.OpenLegacyAsyncForEnrollment(next, reenrolled, h.Log, path);
        Assert.True(recovered.IsAvailable);
        Assert.Equal(0, recovered.ResetAt);
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = Dispatcher(h, handler);
        // The new store cannot authorize a command still bound to the old registration.
        await using (var wrong = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            recovered, _ => Task.FromResult(identity.AgentId)))
            await wrong.ProcessAsync(new[] { Command() }, default);
        Assert.Equal(0, handler.Calls);
        await using (var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            recovered, _ => Task.FromResult(next.AgentId)))
        {
            await processor.ProcessAsync(new[] { Command() }, default);
            await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "new enrollment result");
        }
        Assert.Equal(1, handler.Calls);
        Assert.NotNull(CommandReplayStore.OpenLegacyAsyncForEnrollment(next, reenrolled, h.Log, path).Find(next.AgentId, Command().Id));
        Assert.True(CommandReplayStore.OpenLegacyAsyncForEnrollment(identity,
            reenrolled with { Generation = 3, LastEnrollmentNonce = Guid.NewGuid().ToString("N") }, h.Log, path).ResetAt > 0);
        Assert.Contains(h.Log.Lines, line => line.Contains("re-enrollment with a new agent identity"));
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
