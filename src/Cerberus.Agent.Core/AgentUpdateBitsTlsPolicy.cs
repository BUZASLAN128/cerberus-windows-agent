using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Cerberus.Agent.Core;

/// <summary>Only the compiled, identity-bound development campaign supplies this per-transfer trust.</summary>
public sealed record AgentUpdateBitsTlsPolicy(string RootCertificateBase64, string ArtifactPrefix, DateTimeOffset ExpiresAtUtc)
{
    internal void RequireSource(Uri source)
    {
        if (DateTimeOffset.UtcNow >= ExpiresAtUtc || source.Scheme != Uri.UriSchemeHttps ||
            source.UserInfo.Length != 0 || source.Query.Length != 0 || source.Fragment.Length != 0 ||
            !AgentUpdateManifestValidator.IsAllowedArtifactUri(source, ArtifactPrefix))
            throw new InvalidOperationException("Development BITS TLS authority expired or URL changed.");
    }

    internal bool ValidateCertificate(Uri source, X509Certificate2? certificate, X509Chain? presented = null,
        X509Certificate2Collection? intermediates = null)
    {
        RequireSource(source);
        if (certificate is null || !certificate.MatchesHostname(source.IdnHost, allowWildcards: false, allowCommonName: false))
            return false;
        using var root = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(RootCertificateBase64));
        if (!root.Extensions.OfType<X509BasicConstraintsExtension>().Any(c => c.CertificateAuthority)) return false;
        // Always build to the selected root, including when the OS already trusts another root.
        return BackendTrustAnchors.Validate(certificate, presented, SslPolicyErrors.RemoteCertificateChainErrors,
            new X509Certificate2Collection(root), intermediates);
    }
}
