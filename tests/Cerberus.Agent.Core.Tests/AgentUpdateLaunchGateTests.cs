using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateLaunchGateTests
{
    [Fact]
    public void TryBegin_SuppressesSameUpdateInsideCooldown()
    {
        var gate = new AgentUpdateLaunchGate(TimeSpan.FromMinutes(15));
        var check = Check("0.2.121-dev.121");
        var now = DateTimeOffset.Parse("2026-05-27T10:00:00Z");

        Assert.True(gate.TryBegin(check, now));
        Assert.False(gate.TryBegin(check, now.AddMinutes(1)));
    }

    [Fact]
    public void TryBegin_AllowsSameUpdateAfterCooldown()
    {
        var gate = new AgentUpdateLaunchGate(TimeSpan.FromMinutes(15));
        var check = Check("0.2.121-dev.121");
        var now = DateTimeOffset.Parse("2026-05-27T10:00:00Z");

        Assert.True(gate.TryBegin(check, now));
        Assert.True(gate.TryBegin(check, now.AddMinutes(16)));
    }

    [Fact]
    public void TryBegin_AllowsDifferentVersionInsideCooldown()
    {
        var gate = new AgentUpdateLaunchGate(TimeSpan.FromMinutes(15));
        var now = DateTimeOffset.Parse("2026-05-27T10:00:00Z");

        Assert.True(gate.TryBegin(Check("0.2.121-dev.121"), now));
        Assert.True(gate.TryBegin(Check("0.2.122-dev.122"), now.AddMinutes(1)));
    }

    [Fact]
    public void Clear_AllowsRetryForSameUpdate()
    {
        var gate = new AgentUpdateLaunchGate(TimeSpan.FromMinutes(15));
        var check = Check("0.2.121-dev.121");
        var now = DateTimeOffset.Parse("2026-05-27T10:00:00Z");

        Assert.True(gate.TryBegin(check, now));
        gate.Clear(check);

        Assert.True(gate.TryBegin(check, now.AddMinutes(1)));
    }

    private static AgentUpdateCheckResult Check(string version)
        => new(
            Available: true,
            Required: true,
            Recommended: false,
            Version: version,
            Channel: "dev",
            Reason: "server_update_policy",
            ManifestUrl: "https://github.example/releases/download/dev-latest/update-manifest.json",
            ArtifactKind: "msi");
}
