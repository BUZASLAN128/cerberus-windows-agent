using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Checks the agent's real signing, fingerprint and hashing functions against
/// tests/fixtures/agent-wire-vectors.v1.json.
/// </summary>
public sealed class AgentWireVectorsTests
{
    private static readonly JsonElement Fixture = LoadFixture();

    private static JsonElement LoadFixture()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", "agent-wire-vectors.v1.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.Clone();
    }

    private static readonly string FixturePath = Path.Combine(AppContext.BaseDirectory, "fixtures", "agent-wire-vectors.v1.json");

    private static byte[] FixtureSpki() =>
        Convert.FromBase64String(Fixture.GetProperty("test_key").GetProperty("test_public_key_spki_der").GetString()!);

    private static RSA FixturePublicKey()
    {
        var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(FixtureSpki(), out _);
        return rsa;
    }

    private static bool Verifies(RSA publicKey, string canonical, string signatureBase64) =>
        publicKey.VerifyData(Encoding.UTF8.GetBytes(canonical), Convert.FromBase64String(signatureBase64),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    private static string Str(JsonElement e, string name) => e.GetProperty(name).GetString()!;

    public static IEnumerable<object[]> RequestVectorIds() =>
        Fixture.GetProperty("request_signature").GetProperty("vectors").EnumerateArray()
            .Select(v => new object[] { Str(v, "id") });

    public static IEnumerable<object[]> TelemetryVectorIds() =>
        Fixture.GetProperty("telemetry_section_hash").GetProperty("vectors").EnumerateArray()
            .Select(v => new object[] { Str(v, "id") });

    [Fact]
    public void Fixture_IsVersionedAndCarriesOnlyThePublicKey()
    {
        Assert.Equal("cerberus.agent-wire-vectors", Str(Fixture, "schema"));
        Assert.Equal(1, Fixture.GetProperty("version").GetInt32());
        var raw = File.ReadAllText(FixturePath);
        Assert.DoesNotContain("private_key", raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRIVATE KEY", raw, StringComparison.Ordinal);

        Assert.Equal(
            Str(Fixture.GetProperty("test_key"), "public_key_spki_sha256_hex"),
            Convert.ToHexString(SHA256.HashData(FixtureSpki())).ToLowerInvariant());
    }

    [Theory]
    [MemberData(nameof(RequestVectorIds))]
    public void RequestSigner_ProducesFixtureBodyHashAndCanonical_AndSignaturesVerify(string id)
    {
        var v = Fixture.GetProperty("request_signature").GetProperty("vectors").EnumerateArray()
            .Single(x => Str(x, "id") == id);
        using var runtimeKey = RSA.Create(2048);
        var signer = new RequestSigner(runtimeKey.ExportPkcs8PrivateKeyPem());

        var bodyHash = signer.ComputeBodyHash(Encoding.UTF8.GetBytes(Str(v, "body_utf8")));
        Assert.Equal(Str(v, "expected_body_hash"), bodyHash);

        var canonical = signer.CanonicalString(
            Str(v, "method"), Str(v, "path"), Str(v, "nonce"), v.GetProperty("timestamp").GetInt64(), bodyHash);
        Assert.Equal(Str(v, "expected_canonical"), canonical);

        // Frozen signature verifies with the fixture public key (RSA PKCS#1 v1.5 + SHA-256).
        using var fixturePublic = FixturePublicKey();
        Assert.True(Verifies(fixturePublic, canonical, Str(v, "expected_signature")));

        // The signer's own output uses the same scheme: verifies under PKCS#1 v1.5 with its key.
        Assert.True(Verifies(runtimeKey, canonical, signer.Sign(canonical)));
    }

    [Fact]
    public async Task AgentApiClient_SendsSignedHeadersMatchingFixtureFormat()
    {
        var vector = Fixture.GetProperty("request_signature").GetProperty("vectors").EnumerateArray()
            .Single(x => Str(x, "id") == "post-heartbeat-json-body");
        var path = Str(vector, "path");
        var agentId = path.Split('/')[4];
        var handler = new CapturingHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        using var verifier = RSA.Create(2048);
        var client = new AgentApiClient(http, new FixtureSecretStore(agentId), new FixtureTokenManager(),
            new RequestSigner(verifier.ExportPkcs8PrivateKeyPem()));

        var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        await client.HeartbeatAsync(new { a = 1 }, default);
        await client.HeartbeatAsync(new { a = 1 }, default);
        var after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        Assert.Equal(2, handler.Captured.Count);
        var nonces = new HashSet<string>();
        foreach (var (method, requestPath, headers, body) in handler.Captured)
        {
            Assert.Equal(Str(vector, "method"), method);
            Assert.Equal(path, requestPath);
            Assert.Equal(new[] { "X-Agent-Id", "X-Body-Hash", "X-Nonce", "X-Signature", "X-Timestamp" },
                headers.Keys.Where(k => k.StartsWith("X-", StringComparison.Ordinal)).OrderBy(k => k, StringComparer.Ordinal));
            Assert.Equal(agentId, headers["X-Agent-Id"]);
            Assert.Matches("^[0-9a-f]{32}$", headers["X-Nonce"]);
            Assert.True(nonces.Add(headers["X-Nonce"]));
            Assert.Matches("^[0-9]+$", headers["X-Timestamp"]);
            var ts = long.Parse(headers["X-Timestamp"]);
            Assert.InRange(ts, before, after);
            Assert.Equal(Convert.ToBase64String(SHA256.HashData(body)), headers["X-Body-Hash"]);

            var canonical = $"v1:{method}:{requestPath}:{headers["X-Nonce"]}:{ts}:{headers["X-Body-Hash"]}";
            Assert.True(verifier.VerifyData(Encoding.UTF8.GetBytes(canonical), Convert.FromBase64String(headers["X-Signature"]),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }

    [Fact]
    public void AgentKeyFingerprint_MatchesFixtureUppercaseUnprefixedForm()
    {
        var expected = Str(Fixture.GetProperty("key_fingerprints").GetProperty("agent_key"), "expected");
        var type = typeof(Cerberus.Agent.App.Control.AgentEnrollmentMarker).Assembly
            .GetType("Cerberus.Agent.App.Control.AgentEnrollmentPromotion", throwOnError: true)!;
        var method = type.GetMethod("PublicKeyDigest", BindingFlags.NonPublic | BindingFlags.Static)!;

        var pem = new string(PemEncoding.Write("PUBLIC KEY", FixtureSpki()));

        Assert.Equal(expected, (string)method.Invoke(null, new object[] { pem })!);
    }

    [Fact]
    public void UpdatePublisherPin_MatchesFixtureSha256PrefixedLowercaseForm()
    {
        var expected = Str(Fixture.GetProperty("key_fingerprints").GetProperty("update_publisher_pin"), "expected");
        using var fixturePublic = FixturePublicKey();
        using var issuerKey = RSA.Create(2048);
        var issuerName = new X500DistinguishedName("CN=wire-vector-issuer");
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=wire-vector-test"), new PublicKey(fixturePublic), HashAlgorithmName.SHA256);
        using var certificate = request.Create(
            issuerName, X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1), new byte[] { 1 });

        Assert.Equal(expected, AgentUpdateAuthenticode.PublisherSpkiSha256(certificate));
    }

    [Theory]
    [MemberData(nameof(TelemetryVectorIds))]
    public void SectionHash_MatchesFixtureForSerializedJson(string id)
    {
        var v = Fixture.GetProperty("telemetry_section_hash").GetProperty("vectors").EnumerateArray()
            .Single(x => Str(x, "id") == id);
        var expectedJson = Str(v, "expected_json");
        var expectedHash = Str(v, "expected_sha256");

        Assert.Equal(expectedHash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(expectedJson))).ToLowerInvariant());
        Assert.Equal(expectedHash, AgentSnapshotFactory.HashSection(SectionFor(id)));
    }

    private static object? SectionFor(string id) => id switch
    {
        "dictionary-keeps-insertion-order" => new Dictionary<string, object?> { ["zeta"] = 1, ["alpha"] = "x", ["mid"] = true },
        "number-formats" => new Dictionary<string, object?>
        {
            ["int"] = 42,
            ["neg"] = -7,
            ["double_whole"] = 2.0,
            ["double_frac"] = 0.1,
            ["long_big"] = 9007199254740993L,
            ["decimal"] = 1.50m,
        },
        "camel-case-null-and-escaping" => new { SectionName = "net", Count = 3, Note = (string?)null, Text = "ü<" },
        "null-section" => null,
        _ => throw new InvalidOperationException($"No section builder for vector {id}"),
    };

    [Fact]
    public void SchemaConstants_MatchFixture()
    {
        var c = Fixture.GetProperty("schema_constants");
        Assert.Equal(AgentSchemaVersions.Heartbeat, Str(c, "heartbeat"));
        Assert.Equal(AgentSchemaVersions.Snapshot, Str(c, "snapshot"));
        Assert.Equal(AgentSchemaVersions.Events, Str(c, "events"));
        Assert.Equal(AgentSchemaVersions.ProbeResult, Str(c, "probe_result"));
        Assert.Equal(AgentSchemaVersions.DiagnosticBundle, Str(c, "diagnostic_bundle"));
        Assert.Equal(AgentTelemetryLimits.MaxJsonBytes, c.GetProperty("max_json_bytes").GetInt32());
        Assert.Equal(AgentTelemetryLimits.MaxDiagnosticBundleBytes, c.GetProperty("max_diagnostic_bundle_bytes").GetInt32());
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public List<(string Method, string Path, Dictionary<string, string> Headers, byte[] Body)> Captured { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value));
            var body = request.Content is null ? Array.Empty<byte>() : await request.Content.ReadAsByteArrayAsync(ct);
            Captured.Add((request.Method.Method, request.RequestUri!.AbsolutePath, headers, body));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"pending_commands\":[],\"next_poll_seconds\":60}", Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class FixtureTokenManager : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("token");
        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class FixtureSecretStore(string agentId) : ISecretStore
    {
        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct) => Task.CompletedTask;

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((new AgentIdentity(agentId, "t1"), "refresh", "unused", "http://backend.test", (string?)null, (string?)null));

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
