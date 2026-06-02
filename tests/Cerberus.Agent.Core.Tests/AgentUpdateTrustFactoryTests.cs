using System.Security.Cryptography;
using System.Text;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateTrustFactoryTests
{
    [Fact]
    public void ResolveUpdateManifestPublicKeys_AcceptsCommaSeparatedBase64KeyList()
    {
        using var oldKey = RSA.Create(2048);
        using var signingKey = RSA.Create(2048);
        var oldKeyB64 = PublicKeyB64(oldKey);
        var signingKeyB64 = PublicKeyB64(signingKey);

        var keys = AgentUpdateTrustFactory.ResolveUpdateManifestPublicKeys(
            embeddedBase64: null,
            envPem: null,
            envBase64: $"{oldKeyB64},{signingKeyB64}",
            registryPem: null,
            registryBase64: null);

        Assert.Equal(2, keys.Count);
        Assert.Contains(PublicKeyPem(oldKey).Trim(), keys);
        Assert.Contains(PublicKeyPem(signingKey).Trim(), keys);
    }

    private static string PublicKeyB64(RSA rsa)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem(rsa).Trim()));

    private static string PublicKeyPem(RSA rsa)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN PUBLIC KEY-----");
        builder.AppendLine(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END PUBLIC KEY-----");
        return builder.ToString();
    }
}
