using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
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
