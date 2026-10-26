using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry;

/// <summary>RDP-Tcp listener certificate summary for sessions.rdp_posture.certificate. Only validity and self-signed state leave the host.</summary>
internal sealed record RdpCertificate(string Status, DateTimeOffset? NotAfter, bool? SelfSigned)
{
    internal static readonly RdpCertificate Unavailable = new("unavailable", null, null);
    internal static readonly RdpCertificate NotFound = new("not_found", null, null);

    /// <summary>The listener's own store first, then the machine personal store.</summary>
    internal static readonly string[] StoreOrder = ["Remote Desktop", "My"];

    private const string RdpTcpKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";

    internal object ToPayload() => new
    {
        status = Status,
        not_after_utc = ServerFactText.UtcOrNull(NotAfter),
        self_signed = SelfSigned,
    };

    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private const string RdpAuthOid = "1.3.6.1.4.1.311.54.1.2";

    /// <summary>
    /// The RDP-Tcp registry value SSLCertificateSHA1Hash is written only when a custom certificate is configured;
    /// it then names the certificate. Without it the listener uses its auto-generated self-signed certificate in the
    /// LocalMachine "Remote Desktop" store: the newest server-auth certificate with a private key there is reported.
    /// No WMI or System.Management in this agent.
    /// </summary>
    internal static RdpCertificate Read()
    {
        try
        {
            return Resolve(ReadConfiguredHash(), ReadStore);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            TelemetrySectionCapture.Log?.Warn(
                $"Telemetry section sessions rdp_certificate {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)} at={ExceptionSite.FirstFrame(ex)}");
            return Unavailable;
        }
    }

    /// <summary>
    /// <paramref name="readStore"/> returns the LocalMachine store's certificates (empty when the store does not exist);
    /// the certificates it returns are disposed here.
    /// </summary>
    internal static RdpCertificate Resolve(byte[]? configuredHash, Func<string, IReadOnlyList<X509Certificate2>> readStore)
    {
        var thumbprint = ThumbprintFromHash(configuredHash);
        if (thumbprint is not null)
        {
            foreach (var storeName in StoreOrder)
            {
                var certs = readStore(storeName);
                try
                {
                    var match = certs.FirstOrDefault(c => string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
                    if (match is not null)
                        return FromCertificate(match);
                }
                finally { foreach (var cert in certs) cert.Dispose(); }
            }

            return NotFound;
        }

        var listenerCerts = readStore(StoreOrder[0]);
        try
        {
            var best = listenerCerts
                .Where(c => c.HasPrivateKey && IsServerAuthCapable(c))
                .OrderByDescending(c => c.NotAfter.ToUniversalTime())
                .FirstOrDefault();
            return best is null ? NotFound : FromCertificate(best);
        }
        finally { foreach (var cert in listenerCerts) cert.Dispose(); }
    }

    private static bool IsServerAuthCapable(X509Certificate2 cert)
    {
        var ekus = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
        return ekus.Length == 0
               || ekus.Any(e => e.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value is ServerAuthOid or RdpAuthOid));
    }

    private static byte[]? ReadConfiguredHash()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RdpTcpKey);
        return key?.GetValue("SSLCertificateSHA1Hash") as byte[];
    }

    private static IReadOnlyList<X509Certificate2> ReadStore(string storeName)
    {
        using var store = new X509Store(storeName, StoreLocation.LocalMachine);
        try { store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly); }
        catch (CryptographicException) { return Array.Empty<X509Certificate2>(); } // store does not exist
        return store.Certificates.ToArray();
    }

    internal static RdpCertificate FromCertificate(X509Certificate2 cert)
        => new("ok", new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero), IsSelfSigned(cert));

    /// <summary>Hex thumbprint for a 20-byte SHA-1 hash; null for a missing, empty or all-zero value.</summary>
    internal static string? ThumbprintFromHash(byte[]? hash)
        => hash is { Length: > 0 } && hash.Any(b => b != 0) ? Convert.ToHexString(hash) : null;

    /// <summary>Subject equals issuer and the certificate's signature verifies with its own public key (a copied name alone is not enough).</summary>
    internal static bool IsSelfSigned(X509Certificate2 cert)
    {
        if (!IsSelfSigned(cert.SubjectName.RawData, cert.IssuerName.RawData))
            return false;
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(cert);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid
                | X509VerificationFlags.IgnoreCtlNotTimeValid
                | X509VerificationFlags.IgnoreWrongUsage
                | X509VerificationFlags.IgnoreInvalidBasicConstraints
                | X509VerificationFlags.IgnoreInvalidName
                | X509VerificationFlags.IgnoreInvalidPolicy;
            chain.Build(cert);
            return chain.ChainElements.Count == 1
                   && !chain.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.NotSignatureValid)
                                                  || s.Status.HasFlag(X509ChainStatusFlags.PartialChain)
                                                  || s.Status.HasFlag(X509ChainStatusFlags.UntrustedRoot));
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Subject equals issuer by encoded distinguished name.</summary>
    internal static bool IsSelfSigned(byte[] subjectRaw, byte[] issuerRaw)
        => subjectRaw.AsSpan().SequenceEqual(issuerRaw);
}
