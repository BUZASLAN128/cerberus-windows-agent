using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateStagerTests
{
    [Fact]
    public async Task StageAsync_DownloadsAndWritesVerifiedPlan()
    {
        using var rsa = RSA.Create(2048);
        var artifact = Encoding.UTF8.GetBytes("agent-binary-v1.2.0");
        var hash = Convert.ToHexString(SHA256.HashData(artifact)).ToLowerInvariant();
        var manifest = SignedManifest(rsa, hash);
        var http = new HttpClient(new StaticHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath.EndsWith("manifest.json") == true)
                return new StringContent(
                    JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                    Encoding.UTF8,
                    "application/json");
            return new ByteArrayContent(artifact);
        }));
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-test-" + Guid.NewGuid().ToString("N"));
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPem: PublicKeyPem(rsa),
                ExpectedChannel: "stable",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "1.1.0"),
            root);

        var plan = await stager.StageAsync(UpdateResponse(), CancellationToken.None);

        Assert.NotNull(plan);
        Assert.Equal("1.2.0", plan.Version);
        Assert.True(File.Exists(plan.ArtifactPath));
        Assert.True(File.Exists(Path.Combine(root, "1.2.0", "update-plan.json")));
    }

    [Fact]
    public async Task ApplyPlanAsync_RejectsChecksumMismatch()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-apply-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var artifact = Path.Combine(root, "agent.exe");
        await File.WriteAllTextAsync(artifact, "tampered");
        var plan = new AgentUpdatePlan(
            Version: "1.2.0",
            Channel: "stable",
            ArtifactPath: artifact,
            Sha256: new string('a', 64),
            StagedAtUtc: "2026-05-07T00:00:00Z",
            Reason: "test");
        var planPath = Path.Combine(root, "update-plan.json");
        await File.WriteAllTextAsync(
            planPath,
            JsonSerializer.Serialize(plan, new JsonSerializerOptions(JsonSerializerDefaults.Web)));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AgentUpdateStager.ApplyPlanAsync(planPath, Path.Combine(root, "target.exe"), CancellationToken.None));
        Assert.Contains("checksum mismatch", ex.Message);
    }

    [Fact]
    public async Task ApplyPlanAsync_RejectsPlanOutsideTrustedStagingRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-apply-test-" + Guid.NewGuid().ToString("N"));
        var outside = Path.Combine(Path.GetTempPath(), "cerberus-apply-outside-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(outside);
        var planPath = Path.Combine(outside, "update-plan.json");
        await File.WriteAllTextAsync(planPath, "{}");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AgentUpdateStager.ApplyPlanAsync(
                planPath,
                Path.Combine(root, "target.exe"),
                root,
                Path.Combine(root, "target.exe"),
                CancellationToken.None));

        Assert.Contains("outside trusted staging root", ex.Message);
    }

    [Fact]
    public async Task ApplyPlanAsync_RejectsArtifactOutsideTrustedStagingRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-apply-test-" + Guid.NewGuid().ToString("N"));
        var outside = Path.Combine(Path.GetTempPath(), "cerberus-apply-outside-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(outside);
        var artifact = Path.Combine(outside, "agent.exe");
        await File.WriteAllTextAsync(artifact, "agent-binary");
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("agent-binary"))).ToLowerInvariant();
        var planPath = await WritePlanAsync(root, artifact, hash);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AgentUpdateStager.ApplyPlanAsync(
                planPath,
                Path.Combine(root, "target.exe"),
                root,
                Path.Combine(root, "target.exe"),
                CancellationToken.None));

        Assert.Contains("artifact path is outside", ex.Message);
    }

    [Fact]
    public async Task ApplyPlanAsync_RejectsTargetOutsideAllowlist()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-apply-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var artifact = Path.Combine(root, "agent.exe");
        await File.WriteAllTextAsync(artifact, "agent-binary");
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("agent-binary"))).ToLowerInvariant();
        var planPath = await WritePlanAsync(root, artifact, hash);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            AgentUpdateStager.ApplyPlanAsync(
                planPath,
                Path.Combine(root, "target.exe"),
                root,
                Path.Combine(root, "allowed.exe"),
                CancellationToken.None));

        Assert.Contains("target executable path is not allowed", ex.Message);
    }

    private static HeartbeatResponse UpdateResponse()
        => new(
            PendingCommands: Array.Empty<AgentCommand>(),
            NextPollSeconds: 60,
            ServerTime: 1,
            ServerTimeUtc: "2026-05-07T00:00:00Z",
            CommandBatchSize: 0,
            NextSnapshotSeconds: 300,
            ConfigVersion: "agent-config.v1",
            LifecycleState: "connected",
            RegistrationState: "claimed",
            ClaimRequired: false,
            ManifestVersion: null,
            ManagedAccountManifestHash: null,
            ManifestFreshUntil: null,
            RequireManifestBeforeUnlock: false,
            AgentStatus: "upgrade_required",
            VersionPolicy: null,
            Update: JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
                """{"required":true,"manifest_url":"https://releases.cerberus.local/manifest.json","channel":"stable","reason":"blocked_version"}"""),
            Revoke: null,
            Quarantine: null);

    private static AgentUpdateManifest SignedManifest(RSA rsa, string sha256)
    {
        var unsigned = new AgentUpdateManifest(
            Version: "1.2.0",
            Channel: "stable",
            ArtifactUrl: "https://releases.cerberus.local/Cerberus.Agent.App-stable-1.2.0.exe",
            Sha256: sha256,
            SigningIdentity: "Cerberus Agent Release",
            ReleasedAtUtc: "2026-05-07T00:00:00Z",
            MinimumProtocolVersion: "agent.heartbeat.v1",
            RollbackAllowed: false,
            Signature: "");
        var signature = rsa.SignData(
            Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(unsigned)),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return unsigned with { Signature = Convert.ToBase64String(signature) };
    }

    private static async Task<string> WritePlanAsync(string root, string artifact, string sha256)
    {
        var plan = new AgentUpdatePlan(
            Version: "1.2.0",
            Channel: "stable",
            ArtifactPath: artifact,
            Sha256: sha256,
            StagedAtUtc: "2026-05-07T00:00:00Z",
            Reason: "test");
        var planPath = Path.Combine(root, "update-plan.json");
        await File.WriteAllTextAsync(
            planPath,
            JsonSerializer.Serialize(plan, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        return planPath;
    }

    private static string PublicKeyPem(RSA rsa)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN PUBLIC KEY-----");
        builder.AppendLine(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END PUBLIC KEY-----");
        return builder.ToString();
    }

    private sealed class StaticHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpContent> _content;

        public StaticHandler(Func<HttpRequestMessage, HttpContent> content)
        {
            _content = content;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = _content(request),
                RequestMessage = request,
            });
        }
    }
}
