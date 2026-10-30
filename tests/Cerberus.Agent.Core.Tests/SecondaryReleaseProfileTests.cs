using System.Text;
using System.Security.Cryptography;

namespace Cerberus.Agent.Core.Tests;

public sealed class SecondaryReleaseProfileTests
{
    [Fact]
    public void BothProductAnchorsAndRootEndpointArePassedToEveryPublish()
    {
        WithFixture((primary, secondary) =>
        {
            var result = Check(primary, secondary, "https://collector.example:9443/", "dev");
            Assert.True(result.ExitCode == 0, result.Output);
            Assert.Contains("-p:AgentCommandTrustAnchorsB64=", result.Output);
            Assert.Contains("-p:SecondaryCommandTrustAnchorsB64=", result.Output);
            var encodedUrl = Convert.ToBase64String(Encoding.UTF8.GetBytes("https://collector.example:9443/"));
            Assert.Contains("-p:AgentSecondaryBackendUrlBase64=" + encodedUrl, result.Output);
        });
    }

    [Fact]
    public void OverlappingAuthoritiesAndUnsafeEndpointsAreRejected()
    {
        WithFixture((primary, secondary) =>
        {
            var overlap = Check(primary, primary, "https://collector.example/", "dev");
            Assert.NotEqual(0, overlap.ExitCode);
            Assert.Contains("must be distinct", overlap.Output);
            Assert.NotEqual(0, Check(primary, secondary, "https://user@collector.example/", "dev").ExitCode);
            Assert.NotEqual(0, Check(primary, secondary, "https://collector.example/path", "dev").ExitCode);
            Assert.NotEqual(0, Check(primary, secondary, "http://collector.example/", "dev").ExitCode);
            Assert.NotEqual(0, Check(primary, "", "https://collector.example/", "dev").ExitCode);
        });
    }

    [Fact]
    public void VectorSigningKeyCannotEnterStableProductProfile()
    {
        WithFixture((primary, _) =>
            Assert.NotEqual(0, Check("", primary, "https://collector.example/", "stable").ExitCode));
    }

    private static (int ExitCode, string Output) Check(string primary, string secondary, string url, string channel)
        => ServerPackageStaticTests.RunProfileLib($"'desktop' '{primary}' @{{}} '' '' '{channel}' '' '{url}' '{secondary}'");

    private static void WithFixture(Action<string, string> check)
    {
        var root = ServerPackageStaticTests.FindRepoRoot();
        var primary = Path.Combine(root, "tests", "fixtures", "agent-command-test-anchors.b64");
        using var testKey = RSA.Create(2048);
        var publicKey = Convert.ToBase64String(testKey.ExportSubjectPublicKeyInfo());
        var secondary = Path.Combine(Path.GetTempPath(), $"secondary-public-anchors-{Guid.NewGuid():N}.txt");
        File.WriteAllText(secondary, Convert.ToBase64String(Encoding.UTF8.GetBytes(publicKey)));
        try { check(primary, secondary); }
        finally { File.Delete(secondary); }
    }
}
