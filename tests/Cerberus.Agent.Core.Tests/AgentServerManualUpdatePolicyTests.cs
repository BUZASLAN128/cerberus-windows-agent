using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Support evidence through the production admission/transition owners; no elevated service or installer is run.
public sealed class AgentServerManualUpdatePolicyTests
{
    private static readonly AgentLifecycleSnapshot Active = new() { Generation = 7 };
    private static AgentUpdateJournal Staged() => new()
    {
        AttemptId = "attempt-a", Phase = AgentUpdateStates.AwaitingConsent, LifecycleGeneration = 7,
        ApplyNotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
    };

    [Theory]
    [InlineData("window")]
    [InlineData("quarantine")]
    [InlineData("lifecycle")]
    [InlineData("generation")]
    [InlineData("expired")]
    public void ManualAdmissionUsesServerPolicy(string denial)
    {
        var journal = Staged();
        var lifecycle = Active;
        if (denial == "window") journal = journal with { ApplyNotBeforeUtc = DateTimeOffset.UtcNow.AddHours(1) };
        if (denial == "generation") lifecycle = Active with { Generation = 8 };
        if (denial == "lifecycle") lifecycle = Active with { QuiescenceComplete = false };
        if (denial == "expired") journal = journal with { RequiredInstallAttemptId = "attempt-a",
            InstallRequestAuthorityExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) };
        void Admit() => AgentUpdateLocalService.RequireManualServerPolicy(journal, lifecycle, denial == "quarantine", default);
        if (AgentBuildProfile.IsServer) Assert.ThrowsAny<OperationCanceledException>(Admit);
        else Admit();
    }

    [Fact]
    public void AdministratorManualApplyStillAdmitsDueOptionalRelease()
    {
        var journal = Staged();
        AgentUpdateLocalService.RequireManualServerPolicy(journal, Active, false, default);
        var launched = AgentUpdateLocalService.TransitionLaunchRequested(journal, 7, false, default);
        Assert.Equal("launch_requested", launched.Phase);
    }

    [Fact]
    public void ServerManualApplyRetainsSignedRequestDeadline()
    {
        var expiry = DateTimeOffset.UtcNow.AddHours(1);
        var before = Staged() with { Required = true, RequiredInstallAttemptId = "attempt-a",
            InstallRequestAuthorityExpiresUtc = expiry };
        var launched = AgentUpdateLocalService.TransitionLaunchRequested(before, 7, false, default);
        if (AgentBuildProfile.IsServer)
        {
            Assert.Equal("attempt-a", launched.RequiredInstallAttemptId);
            Assert.Equal(expiry, launched.InstallRequestAuthorityExpiresUtc);
        }
        else Assert.Null(launched.InstallRequestAuthorityExpiresUtc);
    }
}
