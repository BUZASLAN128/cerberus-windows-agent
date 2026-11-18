using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateLabFaultScheduleTests
{
    [Fact]
    public void OnlyTheTenCountedVersionsHaveTheSixScheduledFaultClasses()
    {
        var policy = AgentUpdateLabPolicyTests.Valid();
        string?[] expected = [null, "service-pre-download-exit", "updater-msi-busy-1618", "token-route-429",
            "updater-pre-installer-exit", "service-post-commit-crash", "feed-truncated-artifact",
            "updater-msi-busy-1618", "updater-pre-installer-exit", "token-route-429", "service-pre-download-exit"];
        Assert.Equal(expected, policy.Versions.Select(version => AgentUpdateLabFaults.FaultFor(policy, version)));
        Assert.Equal(new[] { policy.Versions[1], policy.Versions[10] },
            policy.Versions.Where(version => AgentUpdateLabFaults.UsesServiceInterruption(policy, version)));
        Assert.Null(AgentUpdateLabFaults.FaultFor(policy, "0.2.9999"));
        Assert.Null(AgentUpdateLabFaults.FaultFor(null, policy.Versions[1]));
    }
}
