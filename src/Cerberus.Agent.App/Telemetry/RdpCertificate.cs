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

    /// <summary>
    /// Reads the thumbprint the Terminal Services provider exposes as Win32_TSGeneralSetting.SSLCertificateSHA1Hash
    /// directly from its registry backing value (no WMI or System.Management in this agent).
    /// </summary>
    internal static RdpCertificate Read()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RdpTcpKey);
            var thumbprint = ThumbprintFromHash(key?.GetValue("SSLCertificateSHA1Hash") as byte[]);
            if (thumbprint is null)
                return NotFound;

            foreach (var storeName in StoreOrder)
            {
                using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                try { store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly); }
                catch (CryptographicException) { continue; } // store does not exist
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
                if (found.Count > 0)
                {
                    try { return FromCertificate(found[0]); }
                    finally { foreach (var cert in found) cert.Dispose(); }
                }
            }

            return NotFound;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            TelemetrySectionCapture.Log?.Warn(
                $"Telemetry section sessions rdp_certificate {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)} at={ExceptionSite.FirstFrame(ex)}");
            return Unavailable;
        }
    }

    internal static RdpCertificate FromCertificate(X509Certificate2 cert)
        => new("ok", new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero), IsSelfSigned(cert.SubjectName.RawData, cert.IssuerName.RawData));

    /// <summary>Hex thumbprint for a 20-byte SHA-1 hash; null for a missing, empty or all-zero value.</summary>
    internal static string? ThumbprintFromHash(byte[]? hash)
        => hash is { Length: > 0 } && hash.Any(b => b != 0) ? Convert.ToHexString(hash) : null;

    /// <summary>Subject equals issuer by encoded distinguished name.</summary>
    internal static bool IsSelfSigned(byte[] subjectRaw, byte[] issuerRaw)
        => subjectRaw.AsSpan().SequenceEqual(issuerRaw);
}
