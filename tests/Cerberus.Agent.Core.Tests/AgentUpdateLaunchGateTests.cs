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

    [Fact]
    public void PrepareUpdaterRunner_CopiesRunnerOutsideInstallDirectory()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-updater-runner-test-" + Guid.NewGuid().ToString("N"));
        var installDir = Path.Combine(root, "install");
        var stageDir = Path.Combine(root, "stage", "1.2.3");
        Directory.CreateDirectory(installDir);
        Directory.CreateDirectory(stageDir);
        var updaterPath = Path.Combine(installDir, "Cerberus.Agent.Updater.exe");
        var artifactPath = Path.Combine(stageDir, "Cerberus.Agent-dev-1.2.3.msi");
        File.WriteAllText(updaterPath, "updater");
        File.WriteAllText(Path.Combine(installDir, "Cerberus.Agent.Updater.dll"), "dll");
        File.WriteAllText(Path.Combine(installDir, "Cerberus.Agent.Core.dll"), "core");
        File.WriteAllText(Path.Combine(installDir, "Cerberus.Agent.Updater.deps.json"), "{}");
        File.WriteAllText(Path.Combine(installDir, "ignore.txt"), "ignore");
        File.WriteAllText(artifactPath, "msi");

        var runnerPath = AgentUpdateRunnerFiles.Prepare(installDir, stageDir);

        Assert.True(File.Exists(runnerPath));
        Assert.StartsWith(stageDir, runnerPath, StringComparison.OrdinalIgnoreCase);
        Assert.False(string.Equals(installDir, Path.GetDirectoryName(runnerPath), StringComparison.OrdinalIgnoreCase));
        Assert.True(File.Exists(Path.Combine(Path.GetDirectoryName(runnerPath)!, "Cerberus.Agent.Updater.dll")));
        Assert.True(File.Exists(Path.Combine(Path.GetDirectoryName(runnerPath)!, "Cerberus.Agent.Updater.deps.json")));
        Assert.False(File.Exists(Path.Combine(Path.GetDirectoryName(runnerPath)!, "ignore.txt")));
        AgentUpdateRunnerFiles.Validate(Path.GetDirectoryName(runnerPath)!, stageDir);
        File.AppendAllText(Path.Combine(Path.GetDirectoryName(runnerPath)!, "Cerberus.Agent.Core.dll"), "tampered");
        Assert.Throws<InvalidOperationException>(() => AgentUpdateRunnerFiles.Validate(Path.GetDirectoryName(runnerPath)!, stageDir));
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
