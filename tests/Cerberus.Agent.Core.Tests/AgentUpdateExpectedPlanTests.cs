using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateExpectedPlanTests
{
    [Theory]
    [InlineData("version")]
    [InlineData("release")]
    [InlineData("hash")]
    public async Task SignedManifestPlanMismatchStopsBeforeArtifactOrSequenceWrites(string mismatch)
    {
        using var rsa = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var unsigned = new AgentUpdateManifest("msi", "2.0.0", "stable", "https://updates.example.test/agent.msi",
            new string('a', 64), "fixture release", now.AddMinutes(-1).ToString("O"), "agent.heartbeat.v1", false, "",
            AgentUpdateManifest.V2SchemaVersion, 42, now.AddDays(1).ToString("O"), 7, "fixture-signer");
        var manifest = Sign(unsigned, rsa);
        var expected = AgentUpdateExpectedPlan.FromManifest(manifest);
        expected = mismatch switch
        {
            "version" => expected with { Version = "2.0.1" },
            "release" => expected with { ReleaseId = "stable:43" },
            _ => expected with { ArtifactSha256 = new string('b', 64) },
        };
        var requested = new List<string>();
        using var http = Client(manifest, requested);
        var root = Path.Combine(Path.GetTempPath(), "agent-plan-mismatch-" + Guid.NewGuid().ToString("N"));
        var stager = new AgentUpdateStager(http, new(new[] { rsa.ExportSubjectPublicKeyInfoPem() }, "stable",
            new[] { "https://updates.example.test/" }, "1.0.0", AllowedSignerKeyIdentity: "fixture-signer", RequireManifestV2: true), root);
        await Assert.ThrowsAsync<AgentUpdatePlanMismatchException>(() => stager.CheckAsync(
            new AgentUpdateSignal(false, true, "https://updates.example.test/manifest.json", "fixture", "stable", ExpectedPlan: expected), default));
        Assert.Equal(new[] { "/manifest.json" }, requested);
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public async Task MatchingPlanUsesExistingReadOnlyManifestCheckWithoutArtifactDownload()
    {
        using var rsa = RSA.Create(2048);
        var manifest = Sign(new("msi", "2.0.0", "stable", "https://updates.example.test/agent.msi",
            new string('a', 64), "fixture release", "2026-05-07T00:00:00Z", "agent.heartbeat.v1", false, ""), rsa);
        var expected = AgentUpdateExpectedPlan.FromManifest(manifest);
        var requested = new List<string>();
        using var http = Client(manifest, requested);
        var root = Path.Combine(Path.GetTempPath(), "agent-plan-check-" + Guid.NewGuid().ToString("N"));
        var stager = new AgentUpdateStager(http, new(new[] { rsa.ExportSubjectPublicKeyInfoPem() }, "stable",
            new[] { "https://updates.example.test/" }, "1.0.0"), root);
        var result = await stager.CheckAsync(new AgentUpdateSignal(false, true, "https://updates.example.test/manifest.json",
            "fixture", "stable", ExpectedPlan: expected), default);
        Assert.True(result.Available);
        Assert.Equal(manifest.Version, result.Version);
        Assert.Equal("stable:0", expected.ReleaseId);
        Assert.Equal(new[] { "/manifest.json" }, requested);
        Assert.False(Directory.Exists(root));
    }

    private static AgentUpdateManifest Sign(AgentUpdateManifest manifest, RSA rsa)
        => manifest with { Signature = Convert.ToBase64String(rsa.SignData(
            Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(manifest)), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) };
    private static HttpClient Client(AgentUpdateManifest manifest, List<string> requested)
        => new(new ManifestHandler(request =>
        {
            requested.Add(request.RequestUri!.AbsolutePath);
            return new(HttpStatusCode.OK) { RequestMessage = request, Content = new StringContent(JsonSerializer.Serialize(manifest,
                new JsonSerializerOptions(JsonSerializerDefaults.Web)), Encoding.UTF8, "application/json") };
        }));
    private sealed class ManifestHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(respond(request));
    }
}
