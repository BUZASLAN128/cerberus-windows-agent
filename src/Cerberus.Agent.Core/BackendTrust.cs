using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cerberus.Agent.Core;

/// <summary>
/// Backend/collector TLS trust compiled into the binary (build metadata BackendTrustAnchors: comma-separated base64
/// DER certificates). A chain the platform rejects only for chain reasons is re-validated against these anchors alone;
/// without anchors the platform decision stands. No certificate is ever added to a Windows store.
/// </summary>
internal static class BackendTrust
{
    public const string MetadataName = "BackendTrustAnchors";
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    private static readonly Lazy<X509Certificate2Collection> Configured = new(() => ParseAnchors(ReadMetadata()));

    public static bool HasAnchors => Configured.Value.Count > 0;

    public static HttpClientHandler CreateHandler() => Apply(new HttpClientHandler());

    public static HttpClientHandler Apply(HttpClientHandler handler) => Apply(handler, Configured.Value);

    public static HttpClientHandler Apply(HttpClientHandler handler, X509Certificate2Collection anchors)
    {
        if (anchors.Count > 0)
            handler.ServerCertificateCustomValidationCallback = (_, certificate, chain, errors) => Validate(certificate, chain, errors, anchors);
        return handler;
    }

    public static bool Validate(X509Certificate2? certificate, X509Chain? presented, SslPolicyErrors errors, X509Certificate2Collection anchors)
    {
        if (errors == SslPolicyErrors.None)
            return true;
        // Name mismatch and a missing certificate are never repaired by an anchor.
        if (errors != SslPolicyErrors.RemoteCertificateChainErrors || anchors.Count == 0 || certificate is null)
            return false;
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.AddRange(anchors);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthenticationOid));
            if (presented is not null)
                foreach (var element in presented.ChainElements)
                    chain.ChainPolicy.ExtraStore.Add(element.Certificate);
            return chain.Build(certificate);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    internal static X509Certificate2Collection ParseAnchors(string? metadata)
    {
        var anchors = new X509Certificate2Collection();
        foreach (var entry in (metadata ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try { anchors.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(entry))); }
            catch (Exception ex) when (ex is FormatException or CryptographicException) { } // a malformed entry is never an anchor
        }
        return anchors;
    }

    private static string? ReadMetadata()
        => typeof(BackendTrust).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attr => string.Equals(attr.Key, MetadataName, StringComparison.Ordinal))?
            .Value;
}
