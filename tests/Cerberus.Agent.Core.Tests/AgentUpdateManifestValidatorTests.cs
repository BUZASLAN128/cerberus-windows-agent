using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateManifestValidatorTests
{
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
