using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    [Fact]
    public async Task RegistrationChangeStopsLoopWithoutWritingRetryToNewRegistration()
    {
        var handler = new ProductLoopHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.test") };
        var state = new InMemoryAgentLifecycleStateStore();
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner(), state);
        await using var h = EnvelopeHarness.Create();
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(h.StorePath + ".idem", 10, TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromSeconds(1),
            lifecycleState: state, commandProcessor: new RegistrationChangedProcessor(state),
            supportsEvents: false, signedStateOnly: true);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        await loop.RunAsync(stop.Token);

        var next = await state.LoadAsync(default);
        Assert.Equal(1, next.Generation);
        Assert.Equal(AgentLifecycleState.Active, next.State);
        Assert.Null(next.NextAttemptUtc);
        Assert.Equal(0, next.TransientFailureCount);
        Assert.False(stop.IsCancellationRequested);
    }

    private sealed class RegistrationChangedProcessor(IAgentLifecycleStateStore state) : IHeartbeatCommandProcessor
    {
        public async Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct)
        {
            await new AgentLifecycleController(state).CompleteEnrollmentAsync(0, Guid.NewGuid().ToString("N"), ct);
            throw new AgentRegistrationChangedException();
        }
    }

    [Theory]
    [InlineData("reset")]
    [InlineData("binding-blocked")]
    [InlineData("unavailable")]
    public async Task HeartbeatDoesNotAdvertiseAsyncCommandsWithoutDurableReplay(string failure)
    {
        await using var h = EnvelopeHarness.Create();
        var directory = Path.GetDirectoryName(h.StorePath)!;
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "legacy-async.v1.json");
        if (failure == "reset") File.WriteAllText(path, "broken replay");
        if (failure == "binding-blocked") File.WriteAllText(path + ".enrollment", "broken binding");
        if (failure == "unavailable")
        {
            File.WriteAllText(path, "not a directory");
            path = Path.Combine(path, "legacy-async.v1.json");
        }
        var store = CommandReplayStore.OpenLegacyAsyncForEnrollment(new AgentIdentity("agent-1", "tenant-1"),
            new AgentLifecycleSnapshot(), h.Log, path);
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(directory, "idem.json"), 10, TimeSpan.FromMinutes(5)));
        await using var legacy = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1), store,
            _ => Task.FromResult("agent-1"));
        Assert.False(legacy.CanAdvertise);
        var handler = new ProductLoopHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromSeconds(1), commandProcessor: new ProductLoopProcessor(stop),
            supportsEvents: false, legacyAsyncSupported: true, legacyAsyncReady: () => legacy.CanAdvertise);

        await loop.RunAsync(stop.Token);

        Assert.DoesNotContain(LegacyAsyncCommandProcessor.Capability, handler.Body);
    }
}
