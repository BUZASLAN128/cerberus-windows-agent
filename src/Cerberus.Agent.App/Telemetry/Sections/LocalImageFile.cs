using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>
/// Opens a running image for signer reads without using a reparse point. The open uses <c>OBJ_DONT_REPARSE</c>
/// (Windows 10 1803 / Server 2019 and later), so a symlink or junction swapped into the path after
/// <see cref="ProcessesTelemetrySectionCollector.IsLocalFixedPath"/> fails the open instead of leading the service to
/// a share. Older builds reject the flag; there <see cref="OpenByWalk"/> opens the path one component at a time.
/// Every later read (file identity, Authenticode) goes through the returned handle.
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
    private const uint FileDirectoryFile = 0x00000001;
    private const uint FileOpenReparsePoint = 0x00200000;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint FileAccessRights = FileReadData | FileReadAttributes | Synchronize;
    private const uint FileOpenOptions = FileNonDirectoryFile | FileSynchronousIoNonAlert;
    private const uint DirectoryAccessRights = FileReadAttributes | Synchronize;
    private const uint DirectoryOptions = FileDirectoryFile | FileOpenReparsePoint | FileSynchronousIoNonAlert;
    private const int FileAttributeTagInfoClass = 9;
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
    /// Only STATUS_SUCCESS is an open. Every other status means no signer, including success codes such as
    /// STATUS_REPARSE (0x104), STATUS_REPARSE_POINT_ENCOUNTERED (0xC000050B, a reparse point in the path), not found,
    /// denied and STATUS_FILE_IS_A_DIRECTORY. The one exception is <see cref="ShouldRetryWithoutDontReparse"/>.
    /// </summary>
    internal static bool IsOpened(int status) => status == 0;

    /// <summary>
    /// STATUS_INVALID_PARAMETER (0xC000000D) is how a build without OBJ_DONT_REPARSE (Server 2016) rejects the flag;
    /// only then is the open redone by <see cref="OpenByWalk"/>, and the result must pass <see cref="FinalPathMatches"/>.
    /// </summary>
    internal static bool ShouldRetryWithoutDontReparse(int status) => status == unchecked((int)0xC000000D);

    /// <summary>
    /// True when the handle's final path (<c>\\?\</c> + normalized DOS path) is exactly the requested full path,
    /// ignoring case. A junction, symlink or mount point anywhere in the path, a short (8.3) name, a UNC or volume
    /// GUID final path, or a trailing separator difference all fail.
    /// </summary>
    internal static bool FinalPathMatches(string requested, string? final)
        => final is not null
            && final.StartsWith(@"\\?\", StringComparison.Ordinal)
            && string.Equals(final[4..], requested, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Handle opened for synchronous reads on a local volume, or null. The caller disposes it.
    /// </summary>
    internal static SafeFileHandle? TryOpen(string path) => TryOpen(path, forceFallback: false);

    /// <summary><paramref name="forceFallback"/> skips the OBJ_DONT_REPARSE open (tests of the Server 2016 path).</summary>
    internal static SafeFileHandle? TryOpen(string path, bool forceFallback)
    {
        var nt = BuildNtPath(path);
        if (nt is null)
            return null;

        if (!forceFallback)
        {
            var status = Open(null, nt, ObjCaseInsensitive | ObjDontReparse, FileAccessRights, FileOpenOptions, out var handle);
            if (!ShouldRetryWithoutDontReparse(status))
                return Accept(handle, requested: null);
        }

        var full = nt[4..];
        return OpenByWalk(full, out var walked) == WalkStep.Opened ? Accept(walked, requested: full) : null;
    }

    /// <summary>Where the fallback walk stopped; only <see cref="WalkStep.Opened"/> returns a handle.</summary>
    internal enum WalkStep { Opened, InvalidPath, OpenFailed, ReparsePoint, AttributesUnreadable }

    /// <summary>
    /// Components below the drive root (<c>C:\a\b.exe</c> → <c>a</c>, <c>b.exe</c>), or null unless the path is a
    /// drive-letter path whose components are all plain names (not empty, <c>.</c>, <c>..</c>, or holding a colon).
    /// </summary>
    internal static string[]? SplitComponents(string? path)
    {
        if (path is null || path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\')
            return null;
        var parts = path[3..].Split('\\');
        foreach (var part in parts)
        {
            if (part.Length == 0 || part is "." or ".." || part.Contains(':') || part.Contains('/'))
                return null;
        }
        return parts;
    }

    /// <summary>
    /// Server 2016 open that never follows a reparse point: every component, from the drive root down to the file,
    /// is opened relative to its parent with FILE_OPEN_REPARSE_POINT, so a junction or symlink is opened as itself
    /// and rejected by its attributes. Compressed (WOF) or deduplicated images are reparse points too and report no
    /// signer on this path.
    /// </summary>
    internal static WalkStep OpenByWalk(string full, out SafeFileHandle? file)
    {
        file = null;
        var parts = SplitComponents(full);
        if (parts is null)
            return WalkStep.InvalidPath;

        SafeFileHandle? directory = null;
        try
        {
            for (var i = -1; i < parts.Length - 1; i++)
            {
                var name = i < 0 ? @"\??\" + full[..3] : parts[i];
                if (!IsOpened(Open(directory, name, ObjCaseInsensitive, DirectoryAccessRights, DirectoryOptions, out var child)))
                    return WalkStep.OpenFailed;
                directory?.Dispose();
                directory = child!;
                if (CheckNotReparsePoint(directory) is { } rejected)
                    return rejected;
            }

            if (!IsOpened(Open(directory, parts[^1], ObjCaseInsensitive, FileAccessRights, FileOpenOptions | FileOpenReparsePoint, out var opened)))
                return WalkStep.OpenFailed;
            if (CheckNotReparsePoint(opened!) is { } refused)
            {
                opened!.Dispose();
                return refused;
            }
            file = opened;
            return WalkStep.Opened;
        }
        finally
        {
            directory?.Dispose();
        }
    }

    /// <summary>Null for a handle whose FILE_ATTRIBUTE_TAG_INFO shows no reparse point; otherwise why it is refused.</summary>
    private static WalkStep? CheckNotReparsePoint(SafeFileHandle handle)
    {
        var info = new byte[8]; // FILE_ATTRIBUTE_TAG_INFO: FileAttributes, ReparseTag
        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, info, (uint)info.Length))
            return WalkStep.AttributesUnreadable;
        return (BitConverter.ToUInt32(info, 0) & FileAttributeReparsePoint) != 0 ? WalkStep.ReparsePoint : null;
    }

    /// <summary>NtCreateFile of <paramref name="name"/>, relative to <paramref name="root"/> when set.</summary>
    private static int Open(SafeFileHandle? root, string name, uint objectAttributes, uint access, uint options, out SafeFileHandle? handle)
    {
        handle = null;
        var rootAdded = false;
        var nameBuffer = Marshal.StringToHGlobalUni(name);
        var namePtr = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
        try
        {
            root?.DangerousAddRef(ref rootAdded);
            var unicode = new UnicodeString { Length = (ushort)(name.Length * 2), MaximumLength = (ushort)(name.Length * 2), Buffer = nameBuffer };
            Marshal.StructureToPtr(unicode, namePtr, fDeleteOld: false);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = rootAdded ? root!.DangerousGetHandle() : IntPtr.Zero,
                ObjectName = namePtr,
                Attributes = objectAttributes,
            };
            var status = NtCreateFile(
                out var raw, access, ref attributes, out _, IntPtr.Zero, 0, FileShareAll, FileOpen, options, IntPtr.Zero, 0);
            if (IsOpened(status))
                handle = new SafeFileHandle(raw, ownsHandle: true);
            else if (status >= 0 && raw != IntPtr.Zero && raw != new IntPtr(-1))
                _ = NtClose(raw); // an informational status (e.g. STATUS_REPARSE) may still have opened something
            return status;
        }
        finally
        {
            if (rootAdded)
                root!.DangerousRelease();
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(nameBuffer);
        }
    }

    /// <summary>Keeps the handle only on a local volume and, when <paramref name="requested"/> is set, at that exact path.</summary>
    private static SafeFileHandle? Accept(SafeFileHandle? handle, string? requested)
    {
        if (handle is null)
            return null;
        var final = ReadFinalPath(handle);
        if (final is not null && (requested is null || FinalPathMatches(requested, final)) && IsOnLocalVolume(handle, final))
            return handle;
        handle.Dispose();
        return null;
    }

    /// <summary>FILE_NAME_NORMALIZED | VOLUME_NAME_DOS final path, or null.</summary>
    private static string? ReadFinalPath(SafeFileHandle handle)
    {
        var buffer = new char[1024];
        var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        if (length > buffer.Length)
        {
            buffer = new char[length];
            length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        }
        return length == 0 || length >= buffer.Length ? null : new string(buffer, 0, (int)length);
    }

    /// <summary>
    /// The final path is a drive-letter path (<c>\\?\C:\</c>, not <c>\\?\UNC\</c>) and the handle has no remote protocol.
    /// </summary>
    private static bool IsOnLocalVolume(SafeFileHandle handle, string final)
    {
        if (final.Length < 7 || !final.StartsWith(@"\\?\", StringComparison.Ordinal) || !char.IsAsciiLetter(final[4]) || final[5] != ':' || final[6] != '\\')
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
