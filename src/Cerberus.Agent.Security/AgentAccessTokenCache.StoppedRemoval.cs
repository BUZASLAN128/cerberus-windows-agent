using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Security;

public sealed partial class AgentAccessTokenCache
{
    // The Win32 wrapper requests additional access. Keep this open limited to DELETE | SYNCHRONIZE.
    private const uint StoppedFileDeleteAccess = 0x00110000;
    // FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT.
    private const uint StoppedFileOpenOptions = 0x00204060;
    private const uint FileOpen = 1;
    private const uint ObjectCaseInsensitive = 0x40;
    private const int StatusFileIsADirectory = unchecked((int)0xc00000ba);
    private const string InvalidCacheEntry = "The token cache entry is not a regular, single-link file.";

    private static SafeFileHandle OpenStoppedCacheEntry(string path)
    {
        var pathStatus = RtlDosPathNameToNtPathName_U_WithStatus(path, out var name, IntPtr.Zero, IntPtr.Zero);
        if (pathStatus != 0)
            throw new Win32Exception(RtlNtStatusToDosError(pathStatus));
        try
        {
            var namePointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            try
            {
                Marshal.StructureToPtr(name, namePointer, fDeleteOld: false);
                var attributes = new ObjectAttributes
                {
                    Length = Marshal.SizeOf<ObjectAttributes>(),
                    ObjectName = namePointer,
                    Attributes = ObjectCaseInsensitive,
                };
                var status = NtCreateFile(out var handle, StoppedFileDeleteAccess, ref attributes, out _,
                    IntPtr.Zero, 0, FileShare.Read | FileShare.Write, FileOpen, StoppedFileOpenOptions, IntPtr.Zero, 0);
                if (status == 0 && !handle.IsInvalid)
                    return handle;
                handle.Dispose();
                if (status == 0)
                    throw new InvalidOperationException("The token cache entry handle is invalid.");

                var error = RtlNtStatusToDosError(status);
                if (error is 2 or 3)
                    return new SafeFileHandle(IntPtr.Zero, ownsHandle: true);
                var failure = new Win32Exception(error);
                if (status == StatusFileIsADirectory)
                    throw new InvalidOperationException(InvalidCacheEntry, failure);
                throw failure;
            }
            finally { Marshal.FreeHGlobal(namePointer); }
        }
        finally { RtlFreeUnicodeString(ref name); }
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
        public UIntPtr Information;
    }

    [DllImport("ntdll.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int RtlDosPathNameToNtPathName_U_WithStatus(
        string dosPath, out UnicodeString ntPath, IntPtr filePart, IntPtr reserved);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern void RtlFreeUnicodeString(ref UnicodeString name);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes,
        out IoStatusBlock ioStatus, IntPtr allocation, uint fileAttributes, FileShare share, uint disposition,
        uint options, IntPtr ea, uint eaLength);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int RtlNtStatusToDosError(int status);
}
