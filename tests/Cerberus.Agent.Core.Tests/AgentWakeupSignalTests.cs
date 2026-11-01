using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentWakeupSignalTests
{
    [Fact]
    public async Task RepeatedHintsCoalesceIntoOne()
    {
        var signal = new AgentWakeupSignal();
        signal.Signal();
        signal.Signal();
        Assert.True(await signal.WaitAsync(TimeSpan.Zero, CancellationToken.None));
        Assert.False(await signal.WaitAsync(TimeSpan.Zero, CancellationToken.None));
    }

    [Fact]
    public async Task ClearDiscardsPendingHint()
    {
        var signal = new AgentWakeupSignal();
        signal.Signal();
        signal.Clear();
        Assert.False(await signal.WaitAsync(TimeSpan.Zero, CancellationToken.None));
    }

    [Fact]
    public async Task WaitingCanBeCancelledByLifecycleShutdown()
    {
        var signal = new AgentWakeupSignal();
        using var cts = new CancellationTokenSource();
        var waiting = signal.WaitAsync(TimeSpan.FromMinutes(1), cts.Token);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
    }
}
