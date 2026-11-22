#if !CERBERUS_EXCLUDE_UPDATE_CAMPAIGN // Campaign code is not compiled with -p:ExcludeUpdateCampaignCode=true.
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateLabFaultScheduleTests
{
    [Fact]
    public void ServiceFaultsOnFiveEightTenAndUpdaterFaultsOnSixNine()
    {
        var policy = AgentUpdateLabPolicyTests.Valid();
        string?[] expected = [null, null, null, null, null, "service", "updater", null, "service", "updater", "service"];
        Assert.Equal(expected, policy.Versions.Select(version =>
            AgentUpdateLabFaults.UsesServiceInterruption(policy, version) ? "service"
            : AgentUpdateLabFaults.UsesUpdaterInterruption(policy, version) ? "updater" : null));
        Assert.False(AgentUpdateLabFaults.UsesServiceInterruption(policy, "0.2.9999"));
        Assert.False(AgentUpdateLabFaults.UsesUpdaterInterruption(policy, "0.2.9999"));
    }

    [Fact]
    public void ReleaseMetadataKeyMatchesTheCampaignPolicyKey()
        => Assert.Equal(AgentUpdateLabPolicy.MetadataName, AgentUpdateDefaults.LabPolicyMetadataName);
}
#endif
