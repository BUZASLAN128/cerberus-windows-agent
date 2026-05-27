using Cerberus.Agent.App;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateTrustConfigTests
{
    private const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALyJkhxQMzSXnwR86h8srtTefCBiKnmY
        zEJXdcCk1MRCCoC1EaFuFPa9qUAxP3/kWbaHFKccQMcbT3Gcqn9qM2cCAwEAAQ==
        -----END PUBLIC KEY-----
        """;

    [Fact]
    public void ResolveUpdateManifestPublicKey_PrefersPlainPemOverBase64Sources()
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));

        var resolved = ServiceMode.ResolveUpdateManifestPublicKey(
            envPem: PublicKeyPem,
            envBase64: encoded,
            registryPem: PublicKeyPem,
            registryBase64: encoded);

        Assert.Equal(PublicKeyPem.Trim(), resolved);
    }

    [Fact]
    public void ResolveUpdateManifestPublicKey_DecodesBase64WhenPemIsNotProvided()
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));

        var resolved = ServiceMode.ResolveUpdateManifestPublicKey(
            envPem: null,
            envBase64: "",
            registryPem: null,
            registryBase64: encoded);

        Assert.Equal(PublicKeyPem.Trim(), resolved);
    }

    [Fact]
    public void ResolveUpdateManifestPublicKey_PrefersEnvironmentBase64OverRegistryPem()
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));
        using var rsa = RSA.Create(2048);
        var registryPem = ExportPublicKeyPem(rsa);

        var resolved = ServiceMode.ResolveUpdateManifestPublicKey(
            envPem: null,
            envBase64: encoded,
            registryPem: registryPem,
            registryBase64: null);

        Assert.Equal(PublicKeyPem.Trim(), resolved);
    }

    [Fact]
    public void ResolveUpdateManifestPublicKeys_IgnoresInvalidOverrideWhenEmbeddedKeyExists()
    {
        var embedded = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));

        var resolved = ServiceMode.ResolveUpdateManifestPublicKeys(
            embeddedBase64: embedded,
            envPem: "not-a-public-key",
            envBase64: "not-base64",
            registryPem: null,
            registryBase64: null);

        Assert.Equal(new[] { PublicKeyPem.Trim() }, resolved);
    }

    [Fact]
    public void ResolveUpdateManifestPublicKeys_AddsValidOverridesToEmbeddedKeyring()
    {
        using var rsa = RSA.Create(2048);
        var extraPem = ExportPublicKeyPem(rsa);
        var embedded = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));
        var extraEncoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(extraPem));

        var resolved = ServiceMode.ResolveUpdateManifestPublicKeys(
            embeddedBase64: embedded,
            envPem: null,
            envBase64: extraEncoded,
            registryPem: extraPem,
            registryBase64: null);

        Assert.Equal(2, resolved.Count);
        Assert.Contains(PublicKeyPem.Trim(), resolved);
        Assert.Contains(extraPem.Trim(), resolved);
    }

    [Fact]
    public void ResolveConfiguredUpdateManifestUrl_PrefersPublicUpdaterConfigurationWithoutRegistration()
    {
        Assert.Equal(
            "https://github.example/releases/download/dev-latest/manifest.json",
            ServiceMode.ResolveConfiguredUpdateManifestUrl(
                envUrl: " https://github.example/releases/download/dev-latest/manifest.json ",
                legacyEnvUrl: "https://backend.example/ignored.json",
                registryUrl: "https://registry.example/ignored.json"));

        Assert.Equal(
            "https://github.example/releases/download/dev-latest/manifest.json",
            ServiceMode.ResolveConfiguredUpdateManifestUrl(
                envUrl: null,
                legacyEnvUrl: "https://github.example/releases/download/dev-latest/manifest.json",
                registryUrl: "https://registry.example/ignored.json"));

        Assert.Equal(
            "https://registry.example/releases/download/dev-latest/manifest.json",
            ServiceMode.ResolveConfiguredUpdateManifestUrl(
                envUrl: "__cerberus_unset__",
                legacyEnvUrl: null,
                registryUrl: "https://registry.example/releases/download/dev-latest/manifest.json"));
    }

    [Fact]
    public void ResolveConfiguredUpdateManifestUrl_FallsBackToEmbeddedDefault()
    {
        Assert.Equal(
            "https://github.example/releases/download/dev-latest/manifest.json",
            ServiceMode.ResolveConfiguredUpdateManifestUrl(
                envUrl: null,
                legacyEnvUrl: null,
                registryUrl: "__cerberus_unset__",
                defaultUrl: "https://github.example/releases/download/dev-latest/manifest.json"));
    }

    private static string ExportPublicKeyPem(RSA rsa)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN PUBLIC KEY-----");
        builder.AppendLine(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END PUBLIC KEY-----");
        return builder.ToString();
    }
}
