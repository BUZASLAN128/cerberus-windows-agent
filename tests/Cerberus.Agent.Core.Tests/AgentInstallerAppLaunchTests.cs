using System.Security.AccessControl;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Support only: descriptor/launch policy and a user-owned temporary directory; never real ProgramData or App launch.
public sealed class AgentInstallerAppLaunchTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ChildUsesPreparedExtractionRootAndKeepsExistingArguments(bool rollback)
    {
        var root = @"C:\ProgramData\CerberusServerAgent\Privileged\BundleExtraction";
        var proof = "proof with spaces and a \"quote\"";
        var ambient = Environment.GetEnvironmentVariable(AgentInstallerAppLaunch.ExtractionEnvironment);
        var start = AgentInstallerAppLaunch.CreateStartInfo(@"C:\Program Files\Cerberus\Server Agent\app\Cerberus.Agent.exe",
            proof, rollback, () => root);
        Assert.False(start.UseShellExecute);
        Assert.True(start.CreateNoWindow);
        Assert.Equal(@"C:\Program Files\Cerberus\Server Agent\app", start.WorkingDirectory);
        Assert.Equal(root, start.Environment[AgentInstallerAppLaunch.ExtractionEnvironment]);
        Assert.Equal(ambient, Environment.GetEnvironmentVariable(AgentInstallerAppLaunch.ExtractionEnvironment));
        Assert.Equal(rollback ? ["--enroll-rollback"] : new[] { "--enroll-headless", "--proof-from-installer", proof, "--install-service" },
            start.ArgumentList.ToArray());
    }

    [Fact]
    public void FailedPreparationDoesNotReturnLaunchInformation()
        => Assert.Throws<UnauthorizedAccessException>(() => AgentInstallerAppLaunch.CreateStartInfo("app.exe", "proof", false,
            () => throw new UnauthorizedAccessException("weak extraction ACL")));

    [Theory]
    [InlineData(AgentInstallerAppLaunch.ExtractionSddl, true)]
    [InlineData("O:BAG:SYD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)", false)]
    public void TrustedRootAndInheritedCacheDescriptorAreAccepted(string sddl, bool root)
        => AgentInstallerAppLaunch.ValidateExtractionDescriptor(new RawSecurityDescriptor(sddl), root);

    [Theory]
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)")]
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;BU)")]
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)")]
    [InlineData("O:BUG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")]
    [InlineData("O:SYG:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")]
    [InlineData("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)")]
    [InlineData("O:SYG:SYD:P(A;OICINP;FA;;;SY)(A;OICINP;FA;;;BA)")]
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)")]
    [InlineData("O:SYG:SYD:P(A;OICI;GRGX;;;SY)(A;OICI;FA;;;BA)")]
    [InlineData("O:SYG:SYD:P")]
    public void WeakOrIncompleteRootDescriptorFailsClosed(string sddl)
        => Assert.Throws<InvalidOperationException>(() =>
            AgentInstallerAppLaunch.ValidateExtractionDescriptor(new RawSecurityDescriptor(sddl), isRoot: true));

    [Fact]
    public void NullDaclFailsClosed()
    {
        var descriptor = new RawSecurityDescriptor(AgentInstallerAppLaunch.ExtractionSddl) { DiscretionaryAcl = null };
        Assert.Throws<InvalidOperationException>(() => AgentInstallerAppLaunch.ValidateExtractionDescriptor(descriptor, true));
    }

    [Fact]
    public void ExistingWeakTemporaryDirectoryIsRejectedWithoutRepairOrLaunch()
    {
        var parent = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "cerberus-extraction-tests"));
        var root = Path.GetFullPath(Path.Combine(parent, Guid.NewGuid().ToString("N")));
        Assert.StartsWith(parent + Path.DirectorySeparatorChar, root, StringComparison.OrdinalIgnoreCase);
        Directory.CreateDirectory(root);
        var marker = Path.Combine(root, "existing-cache.dll");
        File.WriteAllText(marker, "preserve");
        var before = new DirectoryInfo(root).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All);
        try
        {
            Assert.Throws<InvalidOperationException>(() => AgentInstallerAppLaunch.CreateStartInfo("app.exe", "proof", false, () =>
            {
                AgentInstallerAppLaunch.ValidateExtractionTree(root);
                return root;
            }));
            Assert.Equal(before, new DirectoryInfo(root).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
            Assert.Equal("preserve", File.ReadAllText(marker));
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
