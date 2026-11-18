using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Core.Tests;

internal static class StoppedRemovalNativeFile
{
    internal const uint Delete = 0x10000;
    internal const uint ReadControl = 0x20000;
    internal const uint ReadAttributes = 0x80;
    internal const uint GenericWrite = 0x40000000;
    internal const uint Synchronize = 0x100000;
    internal const uint WinFlags = 0x02200000;
    internal const uint NtOptions = 0x00204020; // OPEN_REPARSE_POINT | OPEN_FOR_BACKUP_INTENT | SYNCHRONOUS_IO_NONALERT.
    internal const uint Share = 3;
    internal const uint OpenExisting = 3;
    internal const int NotAReparsePoint = 4390;

    private static (SafeFileHandle Handle, int Win32) Open(string path, uint access)
    {
        var handle = CreateFileW(path, access, Share, IntPtr.Zero, OpenExisting, WinFlags, IntPtr.Zero);
        return (handle, handle.IsInvalid ? Marshal.GetLastWin32Error() : 0);
    }

    internal static (SafeFileHandle Handle, int Win32) OpenForDisposition(string path, bool directory)
    {
        var ntPath = @"\??\" + path;
        var buffer = Marshal.StringToHGlobalUni(ntPath);
        var nameStorage = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeName>());
        try
        {
            var name = new UnicodeName { Length = checked((ushort)(ntPath.Length * 2)),
                MaximumLength = checked((ushort)((ntPath.Length + 1) * 2)), Buffer = buffer };
            Marshal.StructureToPtr(name, nameStorage, false);
            var attributes = new ObjectAttributes { Length = Marshal.SizeOf<ObjectAttributes>(),
                Name = nameStorage, Attributes = 0x40 }; // OBJ_CASE_INSENSITIVE.
            var status = NtCreateFile(out var value, Delete | Synchronize, ref attributes, out _, IntPtr.Zero,
                0, Share, 1, directory ? NtOptions : NtOptions | 0x40, IntPtr.Zero, 0); // FILE_OPEN; non-directory for files.
            var handle = new SafeFileHandle(value, true);
            return (handle, status == 0 ? 0 : RtlNtStatusToDosError(status));
        }
        finally
        {
            Marshal.FreeHGlobal(nameStorage);
            Marshal.FreeHGlobal(buffer);
        }
    }

    internal static SafeFileHandle RequireOpen(string path, uint access)
    {
        var (handle, error) = Open(path, access);
        if (error == 0) return handle;
        handle.Dispose();
        throw new Win32Exception(error);
    }

    internal static void CreateDirectory(string path, string sddl)
    {
        using var security = new PinnedSecurity(sddl);
        if (!CreateDirectoryW(path, ref security.Attributes)) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    internal static SafeFileHandle CreateRegular(string path, string sddl)
    {
        using var security = new PinnedSecurity(sddl);
        var handle = CreateWithSecurity(path, GenericWrite | ReadControl, Share, ref security.Attributes, 1, WinFlags, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw new Win32Exception(error);
    }

    internal static (bool Success, int Win32, int Bytes) Reparse(SafeFileHandle handle)
    {
        var buffer = new byte[16 * 1024];
        var ok = DeviceIoControl(handle, 0x000900a8, IntPtr.Zero, 0, buffer, buffer.Length, out var bytes, IntPtr.Zero);
        return (ok, ok ? 0 : Marshal.GetLastWin32Error(), bytes);
    }

    internal static (bool Success, int Win32, StandardInfo Info) Standard(SafeFileHandle handle)
    {
        var ok = GetFileInformationByHandleEx(handle, 1, out var info, Marshal.SizeOf<StandardInfo>());
        return (ok, ok ? 0 : Marshal.GetLastWin32Error(), info);
    }

    internal static (int Status, long Id) ReadId(SafeFileHandle handle)
    {
        var status = NtQueryInformationFile(handle, out _, out var id, 8, 6); // FileInternalInformation.
        return (status, id);
    }

    internal static string OpenedPath(SafeFileHandle handle)
    {
        var buffer = new StringBuilder(32768);
        var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 8); // FILE_NAME_OPENED / VOLUME_NAME_DOS.
        if (length == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        if (length >= buffer.Capacity) throw new InvalidOperationException("Handle pathname exceeded its bound.");
        return buffer.ToString();
    }

    internal static string Descriptor(SafeFileHandle handle)
    {
        const uint ownerAndDacl = 5;
        var error = GetSecurityInfo(handle, 1, ownerAndDacl, out _, out _, out _, out _, out var descriptor);
        if (error != 0) throw new Win32Exception((int)error);
        try
        {
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, ownerAndDacl, out var text, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try { return Marshal.PtrToStringUni(text) ?? throw new InvalidOperationException("Missing descriptor text."); }
            finally { _ = LocalFree(text); }
        }
        finally { _ = LocalFree(descriptor); }
    }

    internal static (bool Success, int Win32) Disposition(SafeFileHandle handle)
    {
        byte remove = 1;
        var ok = SetFileInformationByHandle(handle, 4, ref remove, 1);
        return (ok, ok ? 0 : Marshal.GetLastWin32Error());
    }

    private sealed class PinnedSecurity : IDisposable
    {
        private readonly GCHandle _pin;
        internal SecurityAttributes Attributes;

        internal PinnedSecurity(string sddl)
        {
            var descriptor = new RawSecurityDescriptor(sddl);
            var bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            _pin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            Attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = _pin.AddrOfPinnedObject() };
        }

        public void Dispose() => _pin.Free();
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StandardInfo
    {
        public long AllocationSize, EndOfFile;
        public uint LinkCount;
        public byte DeletePending, Directory;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeName { public ushort Length, MaximumLength; public IntPtr Buffer; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory, Name;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatus { public IntPtr Status; public UIntPtr Information; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateWithSecurity(string path, uint access, uint share, ref SecurityAttributes security,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool CreateDirectoryW(string path, ref SecurityAttributes security);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input, int inputSize,
        [Out] byte[] output, int outputSize, out int bytes, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass,
        out StandardInfo info, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass,
        ref byte info, int size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, uint objectType, uint info,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr descriptor, uint revision,
        uint info, out IntPtr text, out uint length);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr value);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(out IntPtr handle, uint access, ref ObjectAttributes attributes, out IoStatus io,
        IntPtr allocation, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationFile(SafeFileHandle handle, out IoStatus io, out long value, uint size, uint infoClass);

    [DllImport("ntdll.dll")]
    private static extern int RtlNtStatusToDosError(int status);
}
