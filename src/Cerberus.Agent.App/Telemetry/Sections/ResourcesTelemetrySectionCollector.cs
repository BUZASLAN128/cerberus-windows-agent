using System.IO;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class ResourcesTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    private readonly ResourceSampler _sampler;

    public ResourcesTelemetrySectionCollector()
        : this(ResourceSampler.Shared)
    {
    }

    internal ResourcesTelemetrySectionCollector(ResourceSampler sampler) => _sampler = sampler;

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
        var window = _sampler.GetWindow(ResourceSampler.WindowSeconds(
            AgentTimingPolicy.Current,
            context.LastHeartbeat?.NextSnapshotSeconds));
        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            cpu_count = Environment.ProcessorCount,
            memory_total_mb = memory.TotalMb,
            memory_available_mb = memory.AvailableMb,
            process_working_set_mb = TelemetryValue.ToMb(Environment.WorkingSet),
            gc_heap_mb = TelemetryValue.ToMb(gc.HeapSizeBytes),
            drives,
            cpu_avg_pct = window.CpuAvgPct,
            cpu_max_pct = window.CpuMaxPct,
            mem_used_avg_mb = window.MemUsedAvgMb,
            mem_used_max_mb = window.MemUsedMaxMb,
            sample_window_s = window.SampleWindowSeconds,
            sample_count = window.SampleCount,
        });
    }
}
