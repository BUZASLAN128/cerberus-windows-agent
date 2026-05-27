using Cerberus.Agent.App;
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
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("registry-key"));

        var resolved = ServiceMode.ResolveUpdateManifestPublicKey(
            envPem: PublicKeyPem,
            envBase64: encoded,
            registryPem: "registry-pem",
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

        var resolved = ServiceMode.ResolveUpdateManifestPublicKey(
            envPem: null,
            envBase64: encoded,
            registryPem: "registry-pem",
            registryBase64: null);

        Assert.Equal(PublicKeyPem.Trim(), resolved);
    }

    [Fact]
    public void ResolveUpdateManifestPublicKey_FailsClosedOnInvalidBase64()
    {
        Assert.Throws<FormatException>(() =>
            ServiceMode.ResolveUpdateManifestPublicKey(
                envPem: null,
                envBase64: "not-base64",
                registryPem: null,
                registryBase64: null));
    }
}
