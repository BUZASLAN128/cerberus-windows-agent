using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core.Tests;

public sealed class InstallerAuthoritySourceTests
{
    [Fact]
    public void InstallerLkgActions_UseSystemServerAuthorityAndCreateOnlyTaskRegistration()
    {
        var root = ServerPackageStaticTests.FindRepoRoot();
        var helper = Path.Combine(root, "src", "Cerberus.Agent.Installer", "Helper");
        var bootstrap = File.ReadAllText(Path.Combine(helper, "Program.LkgBootstrap.cs"));
        var store = File.ReadAllText(Path.Combine(root, "src", "Cerberus.Agent.Core", "AgentUpdateLkgStore.cs"));
        var health = File.ReadAllText(Path.Combine(helper, "Program.Health.cs"));
        Assert.Contains("!OperatingSystem.IsWindows() || !AgentBuildProfile.IsServer || !AgentUpdateSecurity.IsLocalSystem()", bootstrap);
        Assert.Contains("AgentUpdateWatchTask.Delete();", bootstrap);
        Assert.Contains("AgentUpdateWatchTask.CreateIfAbsent();", bootstrap);
        Assert.DoesNotContain("VerifyAndRepair", bootstrap);
        Assert.DoesNotContain("BootstrapLkgWatch", health);
        Assert.Contains("ValidateServerRuntimeImage(runtime, executableHash, trace)", health);

        Assert.Matches(@"(?s)EnsureRoot\(\);.*Path.Combine\(Root, LockFileName\).*ValidateProtectedPath\(lockPath, UpdatesRoot, allowMissing: true\).*FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None\).*BootstrapCore\(.*AgentUpdateWatchTask.CreateIfAbsent\(\);", store);
    }

    [Fact]
    public void InstallerLkgBootstrap_ReleaseRequiresAuthenticodeAndLabRequiresTheExactUpdaterReceipt()
    {
        var root = ServerPackageStaticTests.FindRepoRoot();
        var helper = Path.Combine(root, "src", "Cerberus.Agent.Installer", "Helper");
        var bootstrap = File.ReadAllText(Path.Combine(helper, "Program.LkgBootstrap.cs"));
        var store = File.ReadAllText(Path.Combine(root, "src", "Cerberus.Agent.Core", "AgentUpdateLkgStore.cs"));
        var project = File.ReadAllText(Path.Combine(helper, "Cerberus.Agent.Installer.Helper.csproj"));
        Assert.Contains("IsAdmittedLabArtifact(\"updater\", updaterVersion, sha256)", bootstrap);
        Assert.Contains("AgentInstalledProductVersion.Read, policy?.CampaignId", bootstrap);
        Assert.Contains("policy?.CampaignId, policy is null ? null", bootstrap);
        Assert.Contains("Link=\"AgentUpdateLabRuntimeAdmission.Rollback.cs\"", project);
        Assert.Contains("AgentUpdateAuthenticode.Verify(path, channel, compiledSignerPins, allowUnsignedDevBuild: labCampaignId is not null)", store);
        Assert.Matches(@"(?s)if \(labCampaignId is not null && isAdmittedLabUpdater\?\.Invoke\(updaterVersion, sha256\) != true\).*throw new InvalidOperationException\([^;]+;\s*verifyAuthenticode\(path\);", store);
        Assert.Contains("previous.LabCampaignId == labCampaignId", store);
        Assert.Contains("VerifyUpdater(HostPath, previous.UpdaterVersion, previous.UpdaterSha256);", store);
        Assert.Contains("VerifyUpdater(path, version, sourceHash);", store);
    }

    [Fact]
    public void InstallerAuthority_ValidatesDescendantsBeforeImageChecks()
    {
        var source = File.ReadAllText(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", "Cerberus.Agent.Installer", "Helper", "Program.RuntimeTrust.cs"));
        var method = Regex.Match(source, @"private static void ValidateRuntimeAuthority\(string runtime\)\s*\{(?<body>[\s\S]*?)\n    \}");
        Assert.True(method.Success);
        var body = method.Groups["body"].Value;
        Assert.True(body.IndexOf("AgentUpdateSecurity.ValidateProtectedTree(runtime)", StringComparison.Ordinal) >= 0);
        Assert.True(body.IndexOf("AgentUpdateSecurity.ValidateProtectedTree(runtime)", StringComparison.Ordinal) <
            body.IndexOf("foreach (var name in RuntimeExecutables)", StringComparison.Ordinal));
    }
}
