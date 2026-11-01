using System.Security.Cryptography;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Unit/support: synthetic split bytes and supplied authority outcome, not Authenticode or an installed MSI.
public sealed class AgentInstallerServiceImageGateTests
{
    [Theory]
    [InlineData("service-destination", true)]
    [InlineData("delete", false)]
    [InlineData("source-only", false)]
    [InlineData("foreign-destination", false)]
    [InlineData("no-queue", false)]
    [InlineData("canceled", false)]
    [InlineData("timeout", false)]
    public void OldSplitService_IsDeferredOnlyForItsExactReplacement(string queue, bool allowed)
    {
        InRuntime((runtime, service) =>
        {
            var calls = new List<string>();
            var entries = queue switch
            {
                "service-destination" or "canceled" or "timeout" => new[] { "replacement.tmp", @"\??\" + service },
                "delete" => new[] { service, "" },
                "source-only" => new[] { service, "elsewhere.exe" },
                "foreign-destination" => new[] { "replacement.tmp", Path.Combine(runtime, "other.exe") },
                _ => Array.Empty<string>(),
            };
            bool Run() => AgentInstallerServiceImageGate.Validate(runtime,
                () => calls.Add("authority"),
                () =>
                {
                    calls.Add("exe-hash");
                    if (queue == "canceled") throw new OperationCanceledException();
                    if (queue == "timeout") throw new TimeoutException();
                    Assert.NotEqual(new string('0', 64), Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(service))));
                    return false;
                },
                ready =>
                {
                    calls.Add("launcher-updater-bundles");
                    if (ready) _ = AgentSingleFileBundle.ReadAssembly(service, "Cerberus.Agent.Service.dll");
                }, () => entries);
            if (allowed)
            {
                Assert.False(Run());
                Assert.Equal(new[] { "authority", "exe-hash", "launcher-updater-bundles" }, calls);
            }
            else Assert.ThrowsAny<Exception>(() => Run());
        });
    }

    [Fact]
    public void HashMatchedNonBundle_IsRejectedEvenWithAQueuedReplacement()
        => InRuntime((runtime, service) => Assert.Throws<InvalidDataException>(() =>
            AgentInstallerServiceImageGate.Validate(runtime, () => { }, () => true,
                ready =>
                {
                    Assert.True(ready);
                    _ = AgentSingleFileBundle.ReadAssembly(service, "Cerberus.Agent.Service.dll");
                }, () => new[] { "replacement.tmp", service })));

    [Theory]
    [InlineData("authority")]
    [InlineData("service-read")]
    [InlineData("launcher-updater-bundles")]
    public void PendingService_DoesNotExcuseAuthorityOrOtherBundleFailures(string failure)
        => InRuntime((runtime, service) => Assert.Throws<UnauthorizedAccessException>(() =>
            AgentInstallerServiceImageGate.Validate(runtime,
                () => { if (failure == "authority") throw new UnauthorizedAccessException(); },
                () => failure == "service-read" ? throw new UnauthorizedAccessException() : false,
                _ => throw new UnauthorizedAccessException(), () => new[] { "replacement.tmp", service })));

    [Fact]
    public void MatchingService_StillRunsTheFullBundleCheck()
        => InRuntime((runtime, _) =>
        {
            var calls = new List<string>();
            Assert.True(AgentInstallerServiceImageGate.Validate(runtime, () => calls.Add("authority"),
                () => { calls.Add("hash"); return true; },
                ready => { Assert.True(ready); calls.Add("all-bundles"); },
                () => throw new InvalidOperationException("A matching hash must not read the reboot queue.")));
            Assert.Equal(new[] { "authority", "hash", "all-bundles" }, calls);
        });

    private static void InRuntime(Action<string, string> check)
    {
        var root = Path.Combine(Path.GetTempPath(), "installer-image-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var service = Path.Combine(root, "Cerberus.Agent.Service.exe");
            File.WriteAllText(service, "old split executable fixture");
            check(root, service);
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
