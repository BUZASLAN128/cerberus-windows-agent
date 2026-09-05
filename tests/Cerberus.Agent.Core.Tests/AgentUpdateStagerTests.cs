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
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(Path.Combine(root, "0.9.0"));
        Directory.CreateDirectory(Path.Combine(root, "1.0.0"));
        Directory.CreateDirectory(Path.Combine(root, "1.0.1"));
        Directory.SetCreationTimeUtc(Path.Combine(root, "0.9.0"), DateTime.UtcNow.AddMinutes(-30));
        Directory.SetCreationTimeUtc(Path.Combine(root, "1.0.0"), DateTime.UtcNow.AddMinutes(-20));
        Directory.SetCreationTimeUtc(Path.Combine(root, "1.0.1"), DateTime.UtcNow.AddMinutes(-10));
        var log = new CaptureLogger();
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPems: new[] { PublicKeyPem(rsa) },
                ExpectedChannel: "stable",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "1.1.0"),
            root,
            log);

        var plan = await stager.StageAsync(UpdateResponse(), CancellationToken.None);

        Assert.NotNull(plan);
        Assert.Equal("1.2.0", plan.Version);
        Assert.True(File.Exists(plan.ArtifactPath));
        Assert.True(File.Exists(Path.Combine(Path.GetDirectoryName(plan.ArtifactPath)!, AgentUpdateSecurity.PlanFileName)));
        Assert.NotNull(plan.AttemptId);
        Assert.Equal(plan.AttemptId, new AgentUpdateJournalStore(root).Read().AttemptId);
        Assert.Contains(log.InfoMessages, item => item.Contains("download progress", StringComparison.Ordinal));
        Assert.True(Directory.Exists(Path.Combine(root, "0.9.0")));
    }

    [Fact]
    public async Task CheckAsync_ValidatesManifestWithoutDownloadingArtifact()
    {
        using var rsa = RSA.Create(2048);
        var artifact = Encoding.UTF8.GetBytes("agent-binary-v1.2.0");
        var hash = Convert.ToHexString(SHA256.HashData(artifact)).ToLowerInvariant();
        var manifest = SignedManifest(rsa, hash);
        var requestedPaths = new List<string>();
        var http = new HttpClient(new StaticHandler(request =>
        {
            requestedPaths.Add(request.RequestUri?.AbsolutePath ?? "");
            if (request.RequestUri?.AbsolutePath.EndsWith("manifest.json") == true)
                return new StringContent(
                    JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                    Encoding.UTF8,
                    "application/json");
            return new ByteArrayContent(artifact);
        }));
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-check-test-" + Guid.NewGuid().ToString("N"));
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPems: new[] { PublicKeyPem(rsa) },
                ExpectedChannel: "stable",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "1.1.0"),
            root);

        var check = await stager.CheckAsync(UpdateResponse(), CancellationToken.None);

        Assert.True(check.Available);
        Assert.True(check.Required);
        Assert.Equal("1.2.0", check.Version);
        Assert.Equal(new[] { "/manifest.json" }, requestedPaths);
        Assert.False(Directory.Exists(Path.Combine(root, "1.2.0")));
    }

    [Fact]
    public async Task CheckAsync_UsesDirectManifestSignalWithoutHeartbeatRegistration()
    {
        using var rsa = RSA.Create(2048);
        var artifact = Encoding.UTF8.GetBytes("agent-binary-v1.2.0");
        var hash = Convert.ToHexString(SHA256.HashData(artifact)).ToLowerInvariant();
        var manifest = SignedManifest(rsa, hash);
        var requestedPaths = new List<string>();
        var http = new HttpClient(new StaticHandler(request =>
        {
            requestedPaths.Add(request.RequestUri?.AbsolutePath ?? "");
            if (request.RequestUri?.AbsolutePath.EndsWith("manifest.json") == true)
                return new StringContent(
                    JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                    Encoding.UTF8,
                    "application/json");
            throw new InvalidOperationException("Manual check must not download the artifact.");
        }));
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-direct-check-test-" + Guid.NewGuid().ToString("N"));
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPems: new[] { PublicKeyPem(rsa) },
                ExpectedChannel: "stable",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "1.1.0"),
            root);
        var signal = new AgentUpdateSignal(
            Required: false,
            Recommended: true,
            ManifestUrl: "https://releases.cerberus.local/manifest.json",
            Reason: "manual_update_check",
            Channel: "stable");

        var check = await stager.CheckAsync(signal, CancellationToken.None);

        Assert.True(check.Available);
        Assert.False(check.Required);
        Assert.True(check.Recommended);
        Assert.Equal("manual_update_check", check.Reason);
        Assert.Equal(new[] { "/manifest.json" }, requestedPaths);
        Assert.False(Directory.Exists(Path.Combine(root, "1.2.0")));
    }

    [Fact]
    public async Task CheckAsync_ClassifiesManifestHttpFailureAsUnavailable()
    {
        using var rsa = RSA.Create(2048);
        var http = new HttpClient(new ResponseHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)));
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-manifest-404-test-" + Guid.NewGuid().ToString("N"));
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPems: new[] { PublicKeyPem(rsa) },
                ExpectedChannel: "stable",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "1.1.0"),
            root);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            stager.CheckAsync(UpdateResponse(), CancellationToken.None));

        Assert.Contains("manifest unavailable", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(AgentUpdateErrorCodes.ManifestUnavailable, AgentUpdateErrorCodes.Classify(ex));
    }

    [Fact]
    public async Task CheckAsync_AllowsSignedDevChannelDowngradeForSmokeBuilds()
    {
        using var rsa = RSA.Create(2048);
        var artifact = Encoding.UTF8.GetBytes("agent-binary-v0.2.128");
        var hash = Convert.ToHexString(SHA256.HashData(artifact)).ToLowerInvariant();
        var manifest = SignedManifest(rsa, hash, version: "0.2.128-dev.128", channel: "dev");
        var requestedPaths = new List<string>();
        var http = new HttpClient(new StaticHandler(request =>
        {
            requestedPaths.Add(request.RequestUri?.AbsolutePath ?? "");
            if (request.RequestUri?.AbsolutePath.EndsWith("manifest.json") == true)
                return new StringContent(
                    JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                    Encoding.UTF8,
                    "application/json");
            throw new InvalidOperationException("Manual check must not download the artifact.");
        }));
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-dev-downgrade-check-test-" + Guid.NewGuid().ToString("N"));
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPems: new[] { PublicKeyPem(rsa) },
                ExpectedChannel: "dev",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "0.2.1003.0",
                AllowChannelDowngrade: true),
            root);
        var signal = new AgentUpdateSignal(
            Required: false,
            Recommended: true,
            ManifestUrl: "https://releases.cerberus.local/manifest.json",
            Reason: "manual_update_check",
            Channel: "dev");

        var check = await stager.CheckAsync(signal, CancellationToken.None);

        Assert.True(check.Available);
        Assert.Equal("0.2.128-dev.128", check.Version);
        Assert.Equal("dev", check.Channel);
        Assert.Equal(new[] { "/manifest.json" }, requestedPaths);
        Assert.False(Directory.Exists(Path.Combine(root, "0.2.128-dev.128")));
    }

    [Fact]
    public async Task CheckAsync_ReturnsNoneForSameReleaseCorePrereleaseManifest()
    {
        using var rsa = RSA.Create(2048);
        var artifact = Encoding.UTF8.GetBytes("agent-binary-v1.2.0");
        var hash = Convert.ToHexString(SHA256.HashData(artifact)).ToLowerInvariant();
        var manifest = SignedManifest(rsa, hash, version: "1.2.0-dev.42");
        var requestedPaths = new List<string>();
        var http = new HttpClient(new StaticHandler(request =>
        {
            requestedPaths.Add(request.RequestUri?.AbsolutePath ?? "");
            if (request.RequestUri?.AbsolutePath.EndsWith("manifest.json") == true)
                return new StringContent(
                    JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                    Encoding.UTF8,
                    "application/json");
            throw new InvalidOperationException("Artifact must not be downloaded for same-version update signals.");
        }));
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-same-core-check-test-" + Guid.NewGuid().ToString("N"));
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPems: new[] { PublicKeyPem(rsa) },
                ExpectedChannel: "stable",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "1.2.0.0"),
            root);

        var check = await stager.CheckAsync(UpdateResponse(), CancellationToken.None);

        Assert.False(check.Available);
        Assert.Equal("1.2.0-dev.42", check.Version);
        Assert.Equal("not_newer_than_current", check.Reason);
        Assert.Equal(new[] { "/manifest.json" }, requestedPaths);
        Assert.False(Directory.Exists(Path.Combine(root, "1.2.0-dev.42")));
    }

    [Fact]
    public async Task StageAsync_ReusesAlreadyVerifiedArtifactWithoutDownloadingAgain()
    {
        using var rsa = RSA.Create(2048);
        var artifact = Encoding.UTF8.GetBytes("agent-binary-v1.2.0");
        var hash = Convert.ToHexString(SHA256.HashData(artifact)).ToLowerInvariant();
        var manifest = SignedManifest(rsa, hash);
        var requestedPaths = new List<string>();
        var http = new HttpClient(new StaticHandler(request =>
        {
            requestedPaths.Add(request.RequestUri?.AbsolutePath ?? "");
            if (request.RequestUri?.AbsolutePath.EndsWith("manifest.json") == true)
                return new StringContent(
                    JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                    Encoding.UTF8,
                    "application/json");
            return new ByteArrayContent(artifact);
        }));
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-reuse-test-" + Guid.NewGuid().ToString("N"));
        var stageDir = Path.Combine(root, "1.2.0");
        Directory.CreateDirectory(stageDir);
        await File.WriteAllBytesAsync(
            Path.Combine(stageDir, "Cerberus.Agent-stable-1.2.0.msi"),
            artifact);
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPems: new[] { PublicKeyPem(rsa) },
                ExpectedChannel: "stable",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "1.1.0"),
            root);

        var first = await stager.StageAsync(UpdateResponse(), CancellationToken.None);
        Assert.NotNull(first);
        requestedPaths.Clear();
        var plan = await stager.StageAsync(UpdateResponse(), CancellationToken.None);

        Assert.NotNull(plan);
        Assert.Equal(first.AttemptId, plan.AttemptId);
        Assert.Equal(new[] { "/manifest.json" }, requestedPaths);
        Assert.Equal(artifact, await File.ReadAllBytesAsync(plan.ArtifactPath));
    }

    [Fact]
    public async Task StageAsync_PreservesExistingArtifactWhenReplacementDownloadFailsHash()
    {
        using var rsa = RSA.Create(2048);
        var expectedArtifact = Encoding.UTF8.GetBytes("agent-binary-v1.2.0");
        var existingArtifact = Encoding.UTF8.GetBytes("existing-msi-must-not-be-truncated");
        var corruptDownload = Encoding.UTF8.GetBytes("corrupt-msi");
        var hash = Convert.ToHexString(SHA256.HashData(expectedArtifact)).ToLowerInvariant();
        var manifest = SignedManifest(rsa, hash);
        var http = new HttpClient(new StaticHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath.EndsWith("manifest.json") == true)
                return new StringContent(
                    JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                    Encoding.UTF8,
                    "application/json");
            return new ByteArrayContent(corruptDownload);
        }));
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-preserve-test-" + Guid.NewGuid().ToString("N"));
        var stageDir = Path.Combine(root, "1.2.0");
        Directory.CreateDirectory(stageDir);
        var artifactPath = Path.Combine(stageDir, "Cerberus.Agent-stable-1.2.0.msi");
        await File.WriteAllBytesAsync(artifactPath, existingArtifact);
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPems: new[] { PublicKeyPem(rsa) },
                ExpectedChannel: "stable",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "1.1.0"),
            root);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            stager.StageAsync(UpdateResponse(), CancellationToken.None));

        Assert.Contains("checksum mismatch", ex.Message);
        Assert.Equal(existingArtifact, await File.ReadAllBytesAsync(artifactPath));
        Assert.Empty(Directory.GetFiles(stageDir, "*.part"));
    }

    [Fact]
    public async Task StageAsync_ClassifiesArtifactHttpFailureAsDownloadFailed()
    {
        using var rsa = RSA.Create(2048);
        var expectedArtifact = Encoding.UTF8.GetBytes("agent-binary-v1.2.0");
        var hash = Convert.ToHexString(SHA256.HashData(expectedArtifact)).ToLowerInvariant();
        var manifest = SignedManifest(rsa, hash);
        var http = new HttpClient(new ResponseHandler(request =>
        {
            if (request.RequestUri?.AbsolutePath.EndsWith("manifest.json") == true)
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(manifest, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                        Encoding.UTF8,
                        "application/json"),
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-artifact-404-test-" + Guid.NewGuid().ToString("N"));
        var stager = new AgentUpdateStager(
            http,
            new AgentUpdateTrust(
                ManifestPublicKeyPems: new[] { PublicKeyPem(rsa) },
                ExpectedChannel: "stable",
                AllowedArtifactPrefixes: new[] { "https://releases.cerberus.local/" },
                CurrentVersion: "1.1.0"),
            root);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            stager.StageAsync(UpdateResponse(), CancellationToken.None));

        Assert.Contains("artifact download failed", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(AgentUpdateErrorCodes.DownloadFailed, AgentUpdateErrorCodes.Classify(ex));
    }

    [Fact]
    public async Task ApplyPlanAsync_RejectsChecksumMismatch()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-apply-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var artifact = Path.Combine(root, "agent.exe");
        await File.WriteAllTextAsync(artifact, "tampered");
        var plan = new AgentUpdatePlan(
            ArtifactKind: "msi",
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
        Assert.Equal("Direct update application is disabled.", ex.Message);
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

        Assert.Equal("Direct update application is disabled.", ex.Message);
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

        Assert.Equal("Direct update application is disabled.", ex.Message);
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

        Assert.Equal("Direct update application is disabled.", ex.Message);
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

    private static AgentUpdateManifest SignedManifest(
        RSA rsa,
        string sha256,
        string version = "1.2.0",
        string channel = "stable")
    {
        var unsigned = new AgentUpdateManifest(
            ArtifactKind: "msi",
            Version: version,
            Channel: channel,
            ArtifactUrl: $"https://releases.cerberus.local/Cerberus.Agent-{channel}-{version}.msi",
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
            ArtifactKind: "msi",
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

    private sealed class ResponseHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _response;

        public ResponseHandler(Func<HttpRequestMessage, HttpResponseMessage> response)
        {
            _response = response;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = _response(request);
            response.RequestMessage = request;
            return Task.FromResult(response);
        }
    }

    private sealed class CaptureLogger : IAgentLogger
    {
        public List<string> InfoMessages { get; } = [];

        public void Info(string message) => InfoMessages.Add(message);

        public void Warn(string message) { }

        public void Error(string message, Exception? ex = null) { }
    }
}
