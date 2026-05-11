using System.IO;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class ResourcesTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "resources";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var drives = DriveInfo.GetDrives()
            .Where(d => d.IsReady)
            .Take(8)
            .Select(d => new
            {
                name = d.Name,
                type = d.DriveType.ToString(),
                total_mb = TelemetryValue.ToMb(d.TotalSize),
                free_mb = TelemetryValue.ToMb(d.AvailableFreeSpace),
                used_percent = d.TotalSize <= 0
                    ? 0
                    : (int)Math.Round((1 - (double)d.AvailableFreeSpace / d.TotalSize) * 100),
            })
            .ToArray();

        var gc = GC.GetGCMemoryInfo();
        var memory = TelemetryValue.ReadPhysicalMemory();
        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            cpu_count = Environment.ProcessorCount,
            memory_total_mb = memory.TotalMb,
            memory_available_mb = memory.AvailableMb,
            process_working_set_mb = TelemetryValue.ToMb(Environment.WorkingSet),
            gc_heap_mb = TelemetryValue.ToMb(gc.HeapSizeBytes),
            drives,
        });
    }
}
