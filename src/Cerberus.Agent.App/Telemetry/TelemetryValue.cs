using System.ServiceProcess;
using System.Runtime.InteropServices;
using Cerberus.Agent.Observability;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry;

internal static class TelemetryValue
{
    public static long ToMb(long bytes) => Math.Max(0, bytes / 1024 / 1024);
    public static long ToMb(ulong bytes) => bytes > long.MaxValue ? long.MaxValue : ToMb((long)bytes);

    public static int? ReadDword(RegistryKey root, string path, string name)
    {
        using var key = root.OpenSubKey(path);
        return key?.GetValue(name) is int value ? value : null;
    }

    public static object ReadService(string serviceName)
    {
        try
        {
            using var service = new ServiceController(serviceName);
            return new
            {
                name = serviceName,
                status = service.Status.ToString(),
                can_stop = service.CanStop,
            };
        }
        catch (InvalidOperationException ex)
        {
            return new
            {
                name = serviceName,
                status = "unavailable",
                error = Sanitizer.Redact(ex.Message),
            };
        }
    }

    public static (long? TotalMb, long? AvailableMb) ReadPhysicalMemory()
    {
        var status = new MemoryStatusEx();
        status.Length = (uint)Marshal.SizeOf<MemoryStatusEx>();
        if (!GlobalMemoryStatusEx(ref status))
        {
            return (null, null);
        }

        return (ToMb(status.TotalPhys), ToMb(status.AvailPhys));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);
}
