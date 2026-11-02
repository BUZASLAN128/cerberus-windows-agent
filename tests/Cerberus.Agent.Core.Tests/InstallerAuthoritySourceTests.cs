using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core.Tests;

public sealed class InstallerAuthoritySourceTests
{
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
