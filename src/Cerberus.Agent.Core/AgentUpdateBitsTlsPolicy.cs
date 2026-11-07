using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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

    internal bool ValidateCertificate(Uri source, X509Certificate2? certificate, X509Chain? presented = null)
    {
        RequireSource(source);
        if (certificate is null || !certificate.MatchesHostname(source.IdnHost, allowWildcards: false, allowCommonName: false))
            return false;
        using var root = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(RootCertificateBase64));
        if (!root.Extensions.OfType<X509BasicConstraintsExtension>().Any(c => c.CertificateAuthority)) return false;
        // Always build to the selected root, including when the OS already trusts another root.
        return BackendTrust.Validate(certificate, presented, SslPolicyErrors.RemoteCertificateChainErrors,
            new X509Certificate2Collection(root));
    }
}

// Windows SDK bits10_3.h ABI. The callback runs before the TLS handshake completes / HTTP request is sent.
// https://learn.microsoft.com/windows/win32/api/bits10_3/nf-bits10_3-ibackgroundcopyjobhttpoptions3-setservercertificatevalidationinterface
[ComVisible(true), Guid("4CEC0D02-DEF7-4158-813A-C32A46945FF7"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IAgentUpdateBitsCertificateValidation
{
    [PreserveSig]
    int ValidateServerCertificate(IntPtr job, IntPtr file, uint certLength, IntPtr certData,
        uint certEncodingType, uint certStoreLength, IntPtr certStoreData);
}

[ComVisible(true), ClassInterface(ClassInterfaceType.None), ComDefaultInterface(typeof(IAgentUpdateBitsCertificateValidation))]
public sealed class AgentUpdateBitsCertificateValidation : IAgentUpdateBitsCertificateValidation
{
    private readonly AgentUpdateBitsTlsPolicy _policy;
    private readonly Uri _source;
    private readonly Action<string> _recordProof;
    private int _verified;
    private int _rejected;
    internal bool Verified => Volatile.Read(ref _verified) != 0;
    internal bool Rejected => Volatile.Read(ref _rejected) != 0;

    internal AgentUpdateBitsCertificateValidation(AgentUpdateBitsTlsPolicy policy, Uri source, Action<string> recordProof)
        => (_policy, _source, _recordProof) = (policy, source, recordProof);

    public int ValidateServerCertificate(IntPtr job, IntPtr file, uint certLength, IntPtr certData,
        uint certEncodingType, uint certStoreLength, IntPtr certStoreData)
    {
        try
        {
            if ((certEncodingType & 1) == 0 || certLength is 0 or > 65536 || certData == IntPtr.Zero)
                throw new InvalidOperationException("BITS certificate data is invalid.");
            var bytes = new byte[checked((int)certLength)];
            Marshal.Copy(certData, bytes, 0, bytes.Length);
            using var certificate = X509CertificateLoader.LoadCertificate(bytes);
            // This collector presents a leaf issued directly by the selected root; no OS-store/AIA fallback.
            if (!_policy.ValidateCertificate(_source, certificate))
                throw new InvalidOperationException("BITS certificate is outside the selected development trust.");
            _recordProof(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant());
            Volatile.Write(ref _verified, 1);
            return 0;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException or
            InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            Volatile.Write(ref _rejected, 1);
            return unchecked((int)0x800B0004); // TRUST_E_SUBJECT_NOT_TRUSTED, fail closed before the HTTP request.
        }
    }
}

public sealed partial class AgentUpdateBitsDownloader
{
    private sealed record TlsReceipt(Guid JobId, string AttemptId, string Source, string CertificateSha256, DateTimeOffset Utc);

    private static AgentUpdateBitsCertificateValidation ConfigureCampaignTls(IBackgroundCopyJob job,
        AgentUpdateBitsTlsPolicy policy, Uri source, Guid jobId, string attemptId, string attemptDirectory)
    {
        policy.RequireSource(source);
        if (job is not IBackgroundCopyJobHttpOptions3 options)
            throw new InvalidOperationException("BITS server certificate validation is unavailable on this target.");
        var callback = new AgentUpdateBitsCertificateValidation(policy, source, fingerprint =>
            AgentUpdateDurableFile.Write(Path.Combine(attemptDirectory, "bits-tls.json"), attemptDirectory,
                new TlsReceipt(jobId, attemptId, source.AbsoluteUri, fingerprint, DateTimeOffset.UtcNow)));
        Check(options.GetSecurityFlags(out var flags), "BITS security flags could not be read.");
        // Keep OS name/date/usage checks; unknown-CA is repaired by the actual-connection callback only.
        // No redirects, including HTTPS-to-HTTP. The callback is mandatory and not persisted by BITS.
        Check(options.SetSecurityFlags((flags & ~0x0F1Eu) | 0x0208u), "BITS campaign security flags could not be set.");
        Check(options.SetServerCertificateValidationInterface(callback), "BITS campaign TLS callback could not be attached.");
        return callback;
    }

    [ComImport, Guid("8A9263D3-FD4C-4EDA-9B28-30132A4D4E3C"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IBackgroundCopyJobHttpOptions3
    {
        // All inherited slots are repeated in SDK order; SetServerCertificateValidationInterface precedes MakeCustomHeadersWriteOnly.
        [PreserveSig] int SetClientCertificateByID(int storeLocation, [MarshalAs(UnmanagedType.LPWStr)] string storeName, IntPtr certHashBlob);
        [PreserveSig] int SetClientCertificateByName(int storeLocation, [MarshalAs(UnmanagedType.LPWStr)] string storeName, [MarshalAs(UnmanagedType.LPWStr)] string subjectName);
        [PreserveSig] int RemoveClientCertificate();
        [PreserveSig] int GetClientCertificate(out int storeLocation, out IntPtr storeName, out IntPtr certHashBlob, out IntPtr subjectName);
        [PreserveSig] int SetCustomHeaders([MarshalAs(UnmanagedType.LPWStr)] string? headers);
        [PreserveSig] int GetCustomHeaders(out IntPtr headers);
        [PreserveSig] int SetSecurityFlags(uint flags);
        [PreserveSig] int GetSecurityFlags(out uint flags);
        [PreserveSig] int SetHttpMethod([MarshalAs(UnmanagedType.LPWStr)] string method);
        [PreserveSig] int GetHttpMethod(out IntPtr method);
        [PreserveSig] int SetServerCertificateValidationInterface([MarshalAs(UnmanagedType.IUnknown)] object callback);
        [PreserveSig] int MakeCustomHeadersWriteOnly();
    }
}
