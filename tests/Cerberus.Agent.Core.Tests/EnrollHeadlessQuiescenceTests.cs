using Cerberus.Agent.App;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// H7c: the headless enrollment waits for the service to finish its startup quiescence. Shares FakeHost with EnrollHeadlessModeTests.
public sealed partial class EnrollHeadlessModeTests
{
    private static readonly AgentLifecycleSnapshot Settling = new(AgentLifecycleState.Active, "settling") { QuiescenceComplete = false };

    [Fact]
    public async Task Service_still_finishing_quiescence_is_waited_for_and_then_enrolls()
    {
        var host = new FakeHost { LifecycleSequence = [Settling, Settling, new AgentLifecycleSnapshot()] };

        var (exit, _, _) = await Execute(host, installService: false);

        Assert.Equal(0, exit);
        Assert.Equal(3, host.LifecycleReads);
        Assert.Equal(2, host.DelayCalls);
        Assert.Equal(1, host.Http.Requests.Count);
        Assert.Equal(1, host.Store.SaveCount);
        Assert.DoesNotContain(Proof, host.Log.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Quiescence_still_pending_after_the_bound_exits_seven_without_a_request_or_save()
    {
        var host = new FakeHost { LifecycleSequence = [Settling] };

        var (exit, _, stderr) = await Execute(host, installService: false);

        Assert.Equal(7, exit);
        Assert.Contains("cleanup_pending", stderr, StringComparison.Ordinal);
        Assert.Equal(EnrollHeadlessState.MaxQuiescenceWaitSeconds, host.DelayCalls);
        Assert.Equal(EnrollHeadlessState.MaxQuiescenceWaitSeconds + 1, host.LifecycleReads);
        Assert.Empty(host.Http.Requests);
        Assert.Equal(0, host.Store.SaveCount);
    }

    [Theory]
    [InlineData("agent_revoked")]
    [InlineData("already_enrolled")]
    public async Task Refusals_other_than_cleanup_pending_do_not_wait(string refusal)
    {
        var host = refusal == "agent_revoked"
            ? new FakeHost { Lifecycle = new AgentLifecycleSnapshot(AgentLifecycleState.Retired, "agent_revoked") { QuiescenceComplete = false }, HasCredentials = true }
            : new FakeHost { HasCredentials = true };

        var (exit, _, stderr) = await Execute(host, installService: false);

        Assert.Equal(7, exit);
        Assert.Contains(refusal, stderr, StringComparison.Ordinal);
        Assert.Equal(1, host.LifecycleReads);
        Assert.Equal(0, host.DelayCalls);
        Assert.Empty(host.Http.Requests);
    }

    [Fact]
    public async Task Cancellation_during_the_quiescence_wait_exits_five_without_a_request()
    {
        using var cts = new CancellationTokenSource();
        var host = new FakeHost { LifecycleSequence = [Settling], CancelOnDelay = cts };

        var result = await Execute(host, installService: false, ct: cts.Token);

        Assert.Equal(5, result.Exit);
        Assert.Equal(1, host.DelayCalls);
        Assert.Empty(host.Http.Requests);
        Assert.Equal(0, host.Store.SaveCount);
    }
}
