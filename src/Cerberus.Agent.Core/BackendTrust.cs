using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Cerberus.Agent.Core;

internal static class BackendTrust
{
    public const string MetadataName = BackendTrustAnchors.MetadataName;
    public static bool HasAnchors => BackendTrustAnchors.HasAnchors;

    public static HttpClientHandler CreateHandler() => Apply(new HttpClientHandler { AllowAutoRedirect = false });

    public static HttpClientHandler Apply(HttpClientHandler handler) => Apply(handler, BackendTrustAnchors.Configured);

    public static HttpClientHandler Apply(HttpClientHandler handler, X509Certificate2Collection anchors)
    {
        AgentProxySettings.Apply(handler);
        if (anchors.Count > 0)
            handler.ServerCertificateCustomValidationCallback = (_, certificate, chain, errors) => Validate(certificate, chain, errors, anchors);
        return handler;
    }

    public static bool Validate(X509Certificate2? certificate, X509Chain? presented, SslPolicyErrors errors,
        X509Certificate2Collection anchors, X509Certificate2Collection? intermediates = null)
        => BackendTrustAnchors.Validate(certificate, presented, errors, anchors, intermediates);

    internal static bool OnlyTrustMissing(X509ChainStatus[] statuses)
        => BackendTrustAnchors.OnlyTrustMissing(statuses);

    public static X509Certificate2Collection ParseAnchors(string? metadata)
        => BackendTrustAnchors.ParseAnchors(metadata);
}
