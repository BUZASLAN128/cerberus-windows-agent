using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

    public static string PublisherSpkiSha256(X509Certificate2 certificate)
        => "sha256:" + Convert.ToHexString(SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();

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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public int StructSize;
        public IntPtr FilePath;
        public IntPtr Subject;
        public IntPtr FileHandle;
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
