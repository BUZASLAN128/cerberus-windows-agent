using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentInstallerInvocationTests
{
    [Theory]
    [InlineData("")]
    [InlineData("a0441929-53d0-4a1f-9d86-64b437bd38cd")]
    public void EveryActualWixHelperCommandParsesWithNormalBlankOrLabTransaction(string transaction)
    {
        var path = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", "Cerberus.Agent.Installer", "Package.wxs");
        var package = XDocument.Load(path);
        XNamespace wix = "http://wixtoolset.org/schemas/v4/wxs";
        var operations = new HashSet<string>(["bootstrap", "validate-runtime", "health", "capture", "configure", "stop", "restore", "commit", "ensure-running", "validate-proxy", "lab-commit", "lab-rollback", "enroll", "enroll-rollback"]);
        var tested = 0;
        foreach (var action in package.Descendants(wix + "CustomAction"))
        {
            var command = (string?)action.Attribute("ExeCommand") ?? "";
            var operation = command.Split(' ')[0];
            if (!operations.Contains(operation)) continue;
            command = command.Replace("[ProductCode]", "{7AFD2CB7-7F39-450B-8631-F1B1FC38F83B}")
                .Replace("[APPFOLDER]", @"C:\Program Files\Cerberus\Server Agent\app\")
                .Replace("[CERBERUS_LAB_TRANSACTION]", transaction).Replace("[CERBERUS_UPDATE_REQUIRE_BACKEND]", "1")
                .Replace("[CERBERUS_ENROLLMENT_PROOF]", "test-proof");
            command = Regex.Replace(command, @"\$\(var\.ReleaseVersion\)", "0.2.900");
            command = Regex.Replace(command, @"\$\(var\.[^)]+\)", new string('a', 64));
            var argv = WindowsArgv("helper.exe " + command).Skip(1).ToArray();
            Assert.True(AgentInstallerInvocation.TryParse(argv, out var parsed), (string?)action.Attribute("Id"));
            Assert.Equal(operation, parsed!.Operation);
            if (operation is "bootstrap" or "validate-runtime" or "lab-commit" or "lab-rollback" || operation == "health" && argv.Length == 8)
                Assert.Equal(transaction, parsed.LabTransaction);
            if (operation == "health" && argv.Length >= 7) Assert.True(parsed.RequireBackendContact);
            if (operation is "enroll" or "enroll-rollback") Assert.Null(parsed.LabTransaction);
            if (operation == "enroll") Assert.Equal("test-proof", parsed.EnrollmentProof);
            tested++;
        }
        Assert.True(tested >= 8);
    }

    [Fact]
    public void EnrollmentProofIsNotATransactionAndIsNotPrinted()
    {
        string[] prefix = ["enroll", Guid.NewGuid().ToString("D"), "runtime", "0.2.900", "exe-hash", "assembly-hash"];
        Assert.False(AgentInstallerInvocation.TryParse(prefix, out _));
        Assert.False(AgentInstallerInvocation.TryParse([..prefix, ""], out _));
        Assert.False(AgentInstallerInvocation.TryParse([..prefix, "proof", "extra"], out _));
        Assert.True(AgentInstallerInvocation.TryParse([..prefix, "secret-proof"], out var enrolled));
        Assert.Equal("secret-proof", enrolled!.EnrollmentProof);
        Assert.Null(enrolled.LabTransaction);
        Assert.DoesNotContain("secret-proof", enrolled.ToString());
        prefix[0] = "enroll-rollback";
        Assert.True(AgentInstallerInvocation.TryParse(prefix, out var rollback));
        Assert.Null(rollback!.EnrollmentProof);
        Assert.Null(rollback.LabTransaction);
        Assert.False(AgentInstallerInvocation.TryParse([..prefix, "proof"], out _));
    }

    [Fact]
    public void HealthFlagAndOperationSpecificLengthsRemainStrict()
    {
        string[] args = ["health", Guid.NewGuid().ToString("D"), "runtime", "0.2.900", "exe-hash", "assembly-hash"];
        Assert.True(AgentInstallerInvocation.TryParse(args, out var legacy));
        Assert.False(legacy!.RequireBackendContact);
        Assert.True(AgentInstallerInvocation.TryParse([..args, "1"], out var required));
        Assert.True(required!.RequireBackendContact);
        Assert.True(AgentInstallerInvocation.TryParse([..args, "other"], out var optional));
        Assert.False(optional!.RequireBackendContact);
        Assert.False(AgentInstallerInvocation.TryParse([..args, "1", "transaction", "extra"], out _));
        args[0] = "ensure-running";
        Assert.False(AgentInstallerInvocation.TryParse([..args, "extra"], out _));
        Assert.False(AgentInstallerInvocation.TryParse([], out _));
    }

    private static string[] WindowsArgv(string command)
    {
        var pointer = CommandLineToArgvW(command, out var count);
        if (pointer == IntPtr.Zero) throw new InvalidOperationException("Windows argv parser failed.");
        try { return Enumerable.Range(0, count).Select(i => Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer, i * IntPtr.Size))!).ToArray(); }
        finally { _ = LocalFree(pointer); }
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string command, out int count);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr pointer);
}
