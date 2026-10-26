using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>
/// Opens a running image for signer reads without ever following a reparse point. The open uses
/// <c>OBJ_DONT_REPARSE</c> (Windows 10 1803 / Server 2019 and later), so a symlink or junction swapped into the
/// path after <see cref="ProcessesTelemetrySectionCollector.IsLocalFixedPath"/> fails the open instead of leading
/// the service to a share. Every later read (file identity, Authenticode) goes through the returned handle.
/// </summary>
internal static class LocalImageFile
{
    private const uint ObjCaseInsensitive = 0x00000040;
    private const uint ObjDontReparse = 0x00001000;
    private const uint FileReadData = 0x0001;
    private const uint FileReadAttributes = 0x0080;
    private const uint Synchronize = 0x00100000;
    private const uint FileShareAll = 0x7; // read | write | delete
    private const uint FileOpen = 1;
    private const uint FileSynchronousIoNonAlert = 0x00000020;
    private const uint FileNonDirectoryFile = 0x00000040;
    private const int FileRemoteProtocolInfoClass = 13;
    private const int MaxNameBytes = ushort.MaxValue - 1;

    /// <summary>
    /// NT path (<c>\??\C:\...</c>) for a fully qualified drive-letter path, normalized the same way the reparse walk
    /// in <see cref="ProcessesTelemetrySectionCollector.IsLocalFixedPath"/> sees it. Null for anything else.
    /// </summary>
    internal static string? BuildNtPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
            return null;
        try
        {
            if (!Path.IsPathFullyQualified(path))
                return null;
            var full = Path.GetFullPath(path);
            if (full.Length < 4 || !char.IsAsciiLetter(full[0]) || full[1] != ':' || full[2] != '\\')
                return null;
            var nt = @"\??\" + full;
            return nt.Length * 2 > MaxNameBytes ? null : nt;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    /// <summary>
    /// Only STATUS_SUCCESS is an open. Every other status means no signer and no path fallback, including success
    /// codes such as STATUS_REPARSE (0x104), STATUS_REPARSE_POINT_ENCOUNTERED (0xC000050B, a reparse point in the
    /// path), STATUS_INVALID_PARAMETER (0xC000000D, a build without OBJ_DONT_REPARSE), not found, denied and
    /// STATUS_FILE_IS_A_DIRECTORY.
    /// </summary>
    internal static bool IsOpened(int status) => status == 0;

    /// <summary>
    /// Handle opened for synchronous reads on a local volume, or null. The caller disposes it.
    /// </summary>
    internal static SafeFileHandle? TryOpen(string path)
    {
        var nt = BuildNtPath(path);
        if (nt is null)
            return null;

        var nameBuffer = Marshal.StringToHGlobalUni(nt);
        var namePtr = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        try
        {
            var name = new UnicodeString { Length = (ushort)(nt.Length * 2), MaximumLength = (ushort)(nt.Length * 2), Buffer = nameBuffer };
            Marshal.StructureToPtr(name, namePtr, fDeleteOld: false);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                ObjectName = namePtr,
                Attributes = ObjCaseInsensitive | ObjDontReparse,
            };
            var status = NtCreateFile(
                out var raw, FileReadData | FileReadAttributes | Synchronize, ref attributes, out _, IntPtr.Zero, 0,
                FileShareAll, FileOpen, FileNonDirectoryFile | FileSynchronousIoNonAlert, IntPtr.Zero, 0);
            if (!IsOpened(status))
            {
                if (status >= 0 && raw != IntPtr.Zero && raw != new IntPtr(-1))
                    _ = NtClose(raw); // an informational status (e.g. STATUS_REPARSE) may still have opened something
                return null;
            }

            var handle = new SafeFileHandle(raw, ownsHandle: true);
            if (IsOnLocalVolume(handle))
                return handle;
            handle.Dispose();
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(nameBuffer);
        }
    }

    /// <summary>
    /// The handle resolves to a drive-letter path (<c>\\?\C:\</c>, not <c>\\?\UNC\</c>) and has no remote protocol.
    /// </summary>
    private static bool IsOnLocalVolume(SafeFileHandle handle)
    {
        var buffer = new char[1024];
        var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0 /* VOLUME_NAME_DOS */);
        if (length > buffer.Length)
        {
            buffer = new char[length];
            length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        }
        if (length < 7 || length >= buffer.Length)
            return false;
        var final = new string(buffer, 0, (int)length);
        if (!final.StartsWith(@"\\?\", StringComparison.Ordinal) || !char.IsAsciiLetter(final[4]) || final[5] != ':' || final[6] != '\\')
            return false;

        // FILE_REMOTE_PROTOCOL_INFO (116 bytes, buffer padded); the query only succeeds over a network protocol.
        var protocol = new byte[128];
        return !GetFileInformationByHandleEx(handle, FileRemoteProtocolInfoClass, protocol, (uint)protocol.Length);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtCreateFile(
        out IntPtr handle,
        uint desiredAccess,
        ref ObjectAttributes objectAttributes,
        out IoStatusBlock ioStatus,
        IntPtr allocationSize,
        uint fileAttributes,
        uint shareAccess,
        uint createDisposition,
        uint createOptions,
        IntPtr eaBuffer,
        uint eaLength);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtClose(IntPtr handle);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, [Out] char[] path, uint pathLength, uint flags);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, [Out] byte[] info, uint size);
}
