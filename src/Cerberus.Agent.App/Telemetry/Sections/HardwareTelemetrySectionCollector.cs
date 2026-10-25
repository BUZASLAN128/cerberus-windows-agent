using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>CPU, memory and machine model from the registry and Win32; no WMI.</summary>
internal sealed class HardwareTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    private static readonly TimeSpan CpuSampleGap = TimeSpan.FromMilliseconds(250);

    public string SectionName => "hardware";

    public async ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var cpuUsage = await SampleCpuUsageAsync(ct).ConfigureAwait(false);
        var topology = ReadTopology();
        var memory = TelemetryValue.ReadPhysicalMemory();
        var usedPercent = memory.TotalMb is > 0 && memory.AvailableMb is { } available
            ? (int)Math.Clamp(Math.Round((1 - (double)available / memory.TotalMb.Value) * 100), 0, 100)
            : 0;
        var lastBoot = DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);

        return new
        {
            status = "ok",
            cpu_model = ServerFactText.Clean(ReadRegistryString(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"), 128),
            cpu_sockets = topology.Sockets,
            cpu_cores = topology.Cores,
            cpu_logical = Environment.ProcessorCount,
            cpu_usage_percent = cpuUsage,
            memory_total_mb = memory.TotalMb ?? 0,
            memory_used_percent = usedPercent,
            last_boot_utc = ServerFactText.Utc(lastBoot),
            manufacturer = ServerFactText.CleanOrNull(ReadRegistryString(@"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer"), 64),
            model = ServerFactText.CleanOrNull(ReadRegistryString(@"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"), 64),
        };
    }

    private static string? ReadRegistryString(string path, string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            return key?.GetValue(name) as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
        {
            return null;
        }
    }

    private static async Task<int> SampleCpuUsageAsync(CancellationToken ct)
    {
        if (!GetSystemTimes(out var idle1, out var kernel1, out var user1))
            return 0;
        await Task.Delay(CpuSampleGap, ct).ConfigureAwait(false);
        if (!GetSystemTimes(out var idle2, out var kernel2, out var user2))
            return 0;

        var total = (kernel2 - kernel1) + (user2 - user1);
        var busy = total - (idle2 - idle1);
        return total <= 0 ? 0 : (int)Math.Clamp(Math.Round(busy * 100.0 / total), 0, 100);
    }

    private static (int? Sockets, int? Cores) ReadTopology()
    {
        const int relationAll = 0xFFFF;
        var length = 0;
        GetLogicalProcessorInformationEx(relationAll, IntPtr.Zero, ref length);
        if (length <= 0)
            return (null, null);

        var buffer = Marshal.AllocHGlobal(length);
        try
        {
            if (!GetLogicalProcessorInformationEx(relationAll, buffer, ref length))
                return (null, null);

            int cores = 0, sockets = 0, offset = 0;
            while (offset + 8 <= length)
            {
                var relationship = Marshal.ReadInt32(buffer, offset);
                var size = Marshal.ReadInt32(buffer, offset + 4);
                if (size <= 0)
                    break;
                if (relationship == 0)
                    cores++;
                else if (relationship == 3)
                    sockets++;
                offset += size;
            }

            return (sockets > 0 ? sockets : null, cores > 0 ? cores : null);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out long idle, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetLogicalProcessorInformationEx(int relationship, IntPtr buffer, ref int length);
}
