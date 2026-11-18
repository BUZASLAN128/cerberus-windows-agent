using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateManifestValidatorTests
{
    [Fact]
    public void V2WithoutFloor_KeepsThePreviousCanonicalBytes()
    {
        using var rsa = RSA.Create(2048);
        var manifest = SignedV2(rsa, null);
        var expected = string.Join('\n', "msi", "1.2.0", "stable", "https://releases.cerberus.local/agent/1.2.0.msi",
            new string('a', 64), "Cerberus Agent Release", "2026-05-07T00:00:00Z", "agent.heartbeat.v1", "false",
            "agent.update.manifest.v2", "43", "2026-05-08T00:00:00Z", "100", "test-pin");
        Assert.Equal(expected, AgentUpdateManifestValidator.CanonicalPayload(manifest));
        Assert.Equal("817d1a64703f15890a86ffef1598e133f8d17794033a78cf0bd0943809a589e3",
            AgentUpdateManifestValidator.Digest(manifest));
        Assert.DoesNotContain("min_rollback_version", JsonSerializer.Serialize(manifest));
    }

    [Fact]
    public void StoredV2_AuthenticatesTheOptionalFloorAndIgnoresExpiry()
    {
        using var rsa = RSA.Create(2048);
        var without = SignedV2(rsa, null);
        var withFloor = SignedV2(rsa, "1.1.0");
        Assert.Equal(withFloor, Read(withFloor));
        Assert.Equal(without, Read(without));
        Assert.Contains("signature invalid", Assert.Throws<InvalidOperationException>(() => Read(withFloor with { MinRollbackVersion = null })).Message);
        Assert.Contains("signature invalid", Assert.Throws<InvalidOperationException>(() => Read(without with { MinRollbackVersion = "1.1.0" })).Message);
        Assert.Contains("signature invalid", Assert.Throws<InvalidOperationException>(() => Read(withFloor with { Signature = "AAAA" })).Message);
        Assert.Throws<InvalidOperationException>(() => AgentUpdateManifestValidator.VerifyStoredSignature(
            JsonSerializer.Serialize(withFloor).Replace("\"min_rollback_version\"", "\"tenant_id\":\"a\",\"min_rollback_version\""), [PublicKeyPem(rsa)]));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateManifestValidator.VerifyStoredSignature(
            JsonSerializer.Serialize(withFloor).Replace("\"min_rollback_version\"", "\"MIN_ROLLBACK_VERSION\":\"1.1.0\",\"min_rollback_version\""), [PublicKeyPem(rsa)]));
        Assert.Contains("expired", Assert.Throws<InvalidOperationException>(() => AgentUpdateManifestValidator.ParseAndValidateJson(
            JsonSerializer.Serialize(withFloor), PublicKeyPem(rsa), "stable", [], currentVersion: "1.3.0")).Message);

        AgentUpdateManifest Read(AgentUpdateManifest value) => AgentUpdateManifestValidator.VerifyStoredSignature(
            JsonSerializer.Serialize(value), [PublicKeyPem(rsa)]);
    }

    [Theory]
    [InlineData("1.3.0")]
    [InlineData("release1.1.0")]
    [InlineData("2147483648.0.0")]
    public void StoredV2_RejectsMalformedOrHigherRollbackFloor(string minimum)
    {
        using var rsa = RSA.Create(2048);
        var manifest = SignedV2(rsa, minimum);
        var ex = Assert.Throws<InvalidOperationException>(() => AgentUpdateManifestValidator.VerifyStoredSignature(
            JsonSerializer.Serialize(manifest), [PublicKeyPem(rsa)]));
        Assert.Contains("rollback floor is invalid", ex.Message);
    }

    internal static AgentUpdateManifest SignedV2(RSA rsa, string? minimum)
    {
        var manifest = SignedManifest(rsa) with
        {
            SchemaVersion = AgentUpdateManifest.V2SchemaVersion, Sequence = 43, ArtifactLength = 100,
            ExpiresAtUtc = "2026-05-08T00:00:00Z", SignerKeyIdentity = "test-pin", MinRollbackVersion = minimum,
        };
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(manifest)),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return manifest with { Signature = Convert.ToBase64String(signature) };
    }
    [Fact]
    public void Validate_AcceptsSignedServerOwnedManifest()
    {
        using var rsa = RSA.Create(2048);
        var manifest = SignedManifest(rsa);

        var validated = AgentUpdateManifestValidator.Validate(
            manifest,
            PublicKeyPem(rsa),
            "stable",
            new[] { "https://releases.cerberus.local/" },
            currentVersion: "1.1.0");

        Assert.Equal("1.2.0", validated.Version);
    }

    [Fact]
    public void Validate_AcceptsManifestSignedByAnyTrustedKey()
    {
        using var trusted = RSA.Create(2048);
        using var otherTrusted = RSA.Create(2048);
        var manifest = SignedManifest(otherTrusted);

        var validated = AgentUpdateManifestValidator.Validate(
            manifest,
            new[] { PublicKeyPem(trusted), "not-a-public-key", PublicKeyPem(otherTrusted) },
            "stable",
            new[] { "https://releases.cerberus.local/" },
            currentVersion: "1.1.0");

        Assert.Equal("1.2.0", validated.Version);
    }

    [Fact]
    public void Validate_RejectsBadSignature()
    {
        using var rsa = RSA.Create(2048);
        var manifest = SignedManifest(rsa) with { Sha256 = new string('b', 64) };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.Validate(
                manifest,
                PublicKeyPem(rsa),
                "stable",
                new[] { "https://releases.cerberus.local/" }));
        Assert.Contains("signature invalid", ex.Message);
    }

    [Fact]
    public void Validate_RejectsManifestWhenReleaseTrustKeyDoesNotMatchSigner()
    {
        using var signer = RSA.Create(2048);
        using var staleReleaseKey = RSA.Create(2048);
        var manifest = SignedManifest(signer);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.Validate(
                manifest,
                PublicKeyPem(staleReleaseKey),
                "stable",
                new[] { "https://releases.cerberus.local/" },
                currentVersion: "1.1.0"));

        Assert.Contains("signature invalid", ex.Message);
    }

    [Fact]
    public void Validate_RejectsUnsignedManifestAndDeniedArtifactUrl()
    {
        using var rsa = RSA.Create(2048);
        var unsigned = SignedManifest(rsa) with { Signature = "" };

        var unsignedEx = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.Validate(
                unsigned,
                PublicKeyPem(rsa),
                "stable",
                new[] { "https://releases.cerberus.local/" }));
        Assert.Contains("signature missing", unsignedEx.Message);

        var denied = SignedManifest(rsa) with { ArtifactUrl = "https://evil.example/agent.msi" };
        var deniedEx = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.Validate(
                denied,
                PublicKeyPem(rsa),
                "stable",
                new[] { "https://releases.cerberus.local/" }));
        Assert.Contains("artifact URL denied", deniedEx.Message);
    }

    [Fact]
    public void Validate_RejectsWrongChannelAndTenantUrl()
    {
        using var rsa = RSA.Create(2048);
        var manifest = SignedManifest(rsa, channel: "dev");

        var ex = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.Validate(
                manifest,
                PublicKeyPem(rsa),
                "stable",
                new[] { "https://releases.cerberus.local/" }));
        Assert.Contains("channel mismatch", ex.Message);

        var tenantJson = JsonSerializer.Serialize(SignedManifest(rsa))[..^1]
            + "," + "\"tenant_update_url\":\"https://tenant.example/agent.exe\"}";
        var tenantEx = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.ParseAndValidateJson(
                tenantJson,
                PublicKeyPem(rsa),
                "stable",
                new[] { "https://releases.cerberus.local/" }));
        Assert.Contains("tenant_update_url", tenantEx.Message);
    }

    [Fact]
    public void Validate_BlocksDowngradeUnlessRollbackManifestAllowsIt()
    {
        using var rsa = RSA.Create(2048);
        var downgrade = SignedManifest(rsa, version: "1.1.0", rollbackAllowed: false);

        var ex = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.Validate(
                downgrade,
                PublicKeyPem(rsa),
                "stable",
                new[] { "https://releases.cerberus.local/" },
                currentVersion: "1.2.0"));
        Assert.Contains("downgrade denied", ex.Message);

        var rollback = SignedManifest(rsa, version: "1.1.0", rollbackAllowed: true);
        var validated = AgentUpdateManifestValidator.Validate(
            rollback,
            PublicKeyPem(rsa),
            "stable",
            new[] { "https://releases.cerberus.local/" },
            currentVersion: "1.2.0",
            allowRollbackManifest: true);
        Assert.True(validated.RollbackAllowed);
    }

    [Fact]
    public void Validate_AllowsSignedChannelDowngradeOnlyWhenPolicyAllowsIt()
    {
        using var rsa = RSA.Create(2048);
        var devManifest = SignedManifest(rsa, version: "0.2.128-dev.128", channel: "dev");

        var denied = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.Validate(
                devManifest,
                PublicKeyPem(rsa),
                "dev",
                new[] { "https://releases.cerberus.local/" },
                currentVersion: "0.2.1003.0"));
        Assert.Contains("downgrade denied", denied.Message);

        var validated = AgentUpdateManifestValidator.Validate(
            devManifest,
            PublicKeyPem(rsa),
            "dev",
            new[] { "https://releases.cerberus.local/" },
            currentVersion: "0.2.1003.0",
            allowChannelDowngrade: true);

        Assert.Equal("0.2.128-dev.128", validated.Version);
    }

    [Fact]
    public void Validate_DoesNotLetChannelDowngradeBypassSignature()
    {
        using var rsa = RSA.Create(2048);
        var tampered = SignedManifest(rsa, version: "0.2.128-dev.128", channel: "dev")
            with { Sha256 = new string('b', 64) };

        var ex = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.Validate(
                tampered,
                PublicKeyPem(rsa),
                "dev",
                new[] { "https://releases.cerberus.local/" },
                currentVersion: "0.2.1003.0",
                allowChannelDowngrade: true));

        Assert.Contains("signature invalid", ex.Message);
    }

    [Fact]
    public void Validate_ComparesSemverReleaseCoreWithoutPrereleaseSuffix()
    {
        using var rsa = RSA.Create(2048);
        var manifest = SignedManifest(rsa, version: "1.2.0-dev.42");

        var validated = AgentUpdateManifestValidator.Validate(
            manifest,
            PublicKeyPem(rsa),
            "stable",
            new[] { "https://releases.cerberus.local/" },
            currentVersion: "1.2.0.0");

        Assert.Equal("1.2.0-dev.42", validated.Version);
    }

    private static AgentUpdateManifest SignedManifest(
        RSA rsa,
        string version = "1.2.0",
        string channel = "stable",
        bool rollbackAllowed = false)
    {
        var unsigned = new AgentUpdateManifest(
            ArtifactKind: "msi",
            Version: version,
            Channel: channel,
            ArtifactUrl: $"https://releases.cerberus.local/agent/{version}.msi",
            Sha256: new string('a', 64),
            SigningIdentity: "Cerberus Agent Release",
            ReleasedAtUtc: "2026-05-07T00:00:00Z",
            MinimumProtocolVersion: "agent.heartbeat.v1",
            RollbackAllowed: rollbackAllowed,
            Signature: "");
        var signature = rsa.SignData(
            Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(unsigned)),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return unsigned with { Signature = Convert.ToBase64String(signature) };
    }

    private static string PublicKeyPem(RSA rsa)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN PUBLIC KEY-----");
        builder.AppendLine(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END PUBLIC KEY-----");
        return builder.ToString();
    }
}
