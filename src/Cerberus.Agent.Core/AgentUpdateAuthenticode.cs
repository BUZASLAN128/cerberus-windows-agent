using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

// SYSLIB0057: X509CertificateLoader cannot read the signer of an Authenticode-signed PE file. WinVerifyTrust checks the signature first; the extracted certificate is only used for the signer key pin and the unsigned dev-build check.
#pragma warning disable SYSLIB0057
namespace Cerberus.Agent.Core;

public static class AgentUpdateAuthenticode
{
    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public static void Verify(
        string path,
        string channel,
        string? allowedSignerKeyIdentity,
        bool allowUnsignedDevBuild)
    {
        var isDev = string.Equals(channel, "dev", StringComparison.Ordinal);
        var status = WinVerifyTrustFile(path);
        if (status != 0)
        {
            // A broken, revoked or untrusted signature is never an unsigned development build.
            if (isDev && allowUnsignedDevBuild && status == unchecked((int)0x800B0100) &&
                allowedSignerKeyIdentity == "unsigned-dev" && IsActuallyUnsigned(path))
                return;
            throw new InvalidOperationException("Update Authenticode signature verification failed.");
        }

        if (string.IsNullOrWhiteSpace(allowedSignerKeyIdentity))
            throw new InvalidOperationException("Update signer identity is not configured.");

        try
        {
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            var actual = PublisherSpkiSha256(certificate);
            if (!allowedSignerKeyIdentity.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Any(identity => NormalizeIdentity(actual).Equals(NormalizeIdentity(identity), StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("Update signer identity is not trusted.");
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("Update signer identity could not be read.", ex);
        }
    }

    /// <summary>Verifies the Authenticode signature in-process (WinVerifyTrust) and returns the signer subject.</summary>
    public static bool TryGetValidSignerSubject(string path, out string subject)
    {
        subject = "";
        if (WinVerifyTrustFile(path) != 0)
            return false;
        try
        {
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            subject = certificate.Subject;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Same verification as the path overload, but every read goes through <paramref name="handle"/> (opened for
    /// synchronous reads): the file is never reopened by path. The subject comes from the signer certificate in
    /// WinVerifyTrust's own state, so it belongs to the signature that was verified. <paramref name="displayPath"/>
    /// is only passed as the file name WinVerifyTrust requires.
    /// </summary>
    public static bool TryGetValidSignerSubject(SafeFileHandle handle, string displayPath, out string subject)
    {
        subject = "";
        var added = false;
        var fileInfo = new WinTrustFileInfo { StructSize = Marshal.SizeOf<WinTrustFileInfo>() };
        var fileInfoPtr = IntPtr.Zero;
        var dataPtr = IntPtr.Zero;
        var verifyIssued = false;
        try
        {
            handle.DangerousAddRef(ref added);
            fileInfo.FilePath = Marshal.StringToCoTaskMemUni(displayPath);
            fileInfo.FileHandle = handle.DangerousGetHandle();
            fileInfoPtr = Marshal.AllocHGlobal(fileInfo.StructSize);
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);
            var data = new WinTrustData
            {
                StructSize = Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2,
                RevocationChecks = 0,
                UnionChoice = 1,
                FileInfo = fileInfoPtr,
                StateAction = 1, // WTD_STATEACTION_VERIFY: keep the provider state to read the verified signer
                UrlReference = IntPtr.Zero,
                ProvFlags = 0x00001080,
            };
            dataPtr = Marshal.AllocHGlobal(data.StructSize);
            Marshal.StructureToPtr(data, dataPtr, fDeleteOld: false);
            var actionIdentifier = WinTrustActionGenericVerifyV2;
            verifyIssued = true;
            if (WinVerifyTrust(IntPtr.Zero, ref actionIdentifier, dataPtr) != 0)
                return false;

            var stateData = Marshal.PtrToStructure<WinTrustData>(dataPtr).StateData;
            var providerData = stateData == IntPtr.Zero ? IntPtr.Zero : WTHelperProvDataFromStateData(stateData);
            var signer = providerData == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
            var providerCert = signer == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvCertFromChain(signer, 0);
            // CRYPT_PROVIDER_CERT: DWORD cbStruct, then PCCERT_CONTEXT pCert at pointer alignment.
            var certContext = providerCert == IntPtr.Zero ? IntPtr.Zero : Marshal.ReadIntPtr(providerCert, IntPtr.Size);
            if (certContext == IntPtr.Zero)
                return false;
            using var certificate = new X509Certificate2(certContext);
            subject = certificate.Subject;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            if (verifyIssued)
            {
                // WTD_STATEACTION_CLOSE releases the provider state kept by the verify call.
                var closing = Marshal.PtrToStructure<WinTrustData>(dataPtr);
                closing.StateAction = 2;
                Marshal.StructureToPtr(closing, dataPtr, fDeleteOld: false);
                var actionIdentifier = WinTrustActionGenericVerifyV2;
                _ = WinVerifyTrust(IntPtr.Zero, ref actionIdentifier, dataPtr);
            }
            if (dataPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(dataPtr);
            if (fileInfoPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(fileInfoPtr);
            Marshal.FreeCoTaskMem(fileInfo.FilePath);
            if (added)
                handle.DangerousRelease();
        }
    }

    public static string PublisherSpkiSha256(X509Certificate2 certificate)
        => AgentKeyFingerprint.FromSubjectPublicKeyInfo(certificate.PublicKey.ExportSubjectPublicKeyInfo());

    private static bool IsActuallyUnsigned(string path)
    {
        try
        {
            using var certificate = X509Certificate.CreateFromSignedFile(path);
            return false;
        }
        catch (CryptographicException)
        {
            return true;
        }
    }

    private static int WinVerifyTrustFile(string path)
    {
        var fileInfo = new WinTrustFileInfo
        {
            StructSize = Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath = Marshal.StringToCoTaskMemUni(path),
        };
        var fileInfoPtr = Marshal.AllocHGlobal(fileInfo.StructSize);
        var data = new WinTrustData
        {
            StructSize = Marshal.SizeOf<WinTrustData>(),
            UiChoice = 2,
            RevocationChecks = 0,
            UnionChoice = 1,
            FileInfo = fileInfoPtr,
            StateAction = 0,
            UrlReference = IntPtr.Zero,
            // Verification must not create background certificate traffic in a dormant lifecycle.
            ProvFlags = 0x00001080,
        };
        var dataPtr = Marshal.AllocHGlobal(data.StructSize);
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);
            Marshal.StructureToPtr(data, dataPtr, fDeleteOld: false);
            var actionIdentifier = WinTrustActionGenericVerifyV2;
            return WinVerifyTrust(IntPtr.Zero, ref actionIdentifier, dataPtr);
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustData>(dataPtr);
            Marshal.FreeHGlobal(dataPtr);
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPtr);
            Marshal.FreeHGlobal(fileInfoPtr);
            Marshal.FreeCoTaskMem(fileInfo.FilePath);
        }
    }

    private static string NormalizeIdentity(string value)
        => value.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ? value[7..].ToUpperInvariant() : value.ToUpperInvariant();

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(
        IntPtr windowHandle,
        ref Guid actionIdentifier,
        IntPtr trustData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr providerData,
        uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
        uint counterSignerIndex);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint certIndex);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        // WINTRUST_FILE_INFO order: cbStruct, pcwszFilePath, hFile, pgKnownSubject.
        public int StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public int StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UIContext;
        public IntPtr SignatureSettings;
    }
}
