using System.Runtime.InteropServices;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Telemetry;

/// <summary>
/// Samples total system CPU % and used physical memory on a fixed interval into a bounded ring
/// buffer. Reads are non-destructive: every reader gets the same answer for the same window.
/// </summary>
internal sealed class ResourceSampler
{
    internal static readonly TimeSpan DefaultInterval = TimeSpan.FromSeconds(5);
    internal const int MinWindowSeconds = 60;
    internal const int MaxBufferSeconds = 3600;

    // One sampler per process: every resources collector reads the same samples.
    internal static ResourceSampler Shared { get; } = new(
        TimeProvider.System,
        DefaultInterval,
        SharedBufferSeconds(AgentTimingPolicy.Current.Bounds.SnapshotCeiling));

    private readonly object _gate = new();
    private readonly TimeProvider _time;
    private readonly TimeSpan _interval;
    private readonly DateTimeOffset[] _at;
    private readonly double[] _cpu;
    private readonly long[] _memMb;
    private int _next;
    private int _count;
    private int _running;

    internal ResourceSampler(TimeProvider time, TimeSpan interval, int bufferSeconds = MaxBufferSeconds)
    {
        _time = time;
        _interval = interval;
        var capacity = (int)Math.Ceiling(bufferSeconds / interval.TotalSeconds) + 2;
        _at = new DateTimeOffset[capacity];
        _cpu = new double[capacity];
        _memMb = new long[capacity];
    }

    /// <summary>Ring length in seconds: the snapshot ceiling, but never less than the minimum window a reader may ask for.</summary>
    internal static int SharedBufferSeconds(int snapshotCeiling) => Math.Clamp(snapshotCeiling, MinWindowSeconds, MaxBufferSeconds);

    internal int Capacity => _at.Length;

    /// <summary>Window length: the effective snapshot delay, clamped to [60 s, snapshot ceiling].</summary>
    internal static int WindowSeconds(AgentTimingPolicy policy, int? serverSnapshotSeconds)
    {
        var effective = policy.SnapshotDelaySeconds(serverSnapshotSeconds ?? 0);
        return Math.Clamp(effective, MinWindowSeconds, Math.Max(MinWindowSeconds, policy.Bounds.SnapshotCeiling));
    }

    /// <summary>Runs until cancelled. A second concurrent call returns immediately.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        if (Interlocked.Exchange(ref _running, 1) == 1)
            return;

        try
        {
            using var timer = new PeriodicTimer(_interval, _time);
            var previous = ReadSystemTimes();
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                var current = ReadSystemTimes();
                var cpu = previous.HasValue && current.HasValue
                    ? CpuPercent(previous.Value, current.Value)
                    : null;
                previous = current;
                var memory = TelemetryValue.ReadPhysicalMemory();
                if (cpu.HasValue && memory.TotalMb.HasValue && memory.AvailableMb.HasValue)
                    AddSample(cpu.Value, Math.Max(0, memory.TotalMb.Value - memory.AvailableMb.Value));
            }
        }
        catch (OperationCanceledException)
        {
            // Expected during service shutdown.
        }
        finally
        {
            Volatile.Write(ref _running, 0);
        }
    }

    internal void AddSample(double cpuPercent, long usedMb)
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            _at[_next] = now;
            _cpu[_next] = cpuPercent;
            _memMb[_next] = usedMb;
            _next = (_next + 1) % _at.Length;
            if (_count < _at.Length)
                _count++;
        }
    }

    /// <summary>Aggregates samples taken within the last <paramref name="windowSeconds"/>; does not consume them.</summary>
    public ResourceWindow GetWindow(int windowSeconds)
    {
        var since = _time.GetUtcNow() - TimeSpan.FromSeconds(windowSeconds);
        lock (_gate)
        {
            int used = 0;
            double cpuSum = 0, cpuMax = 0;
            long memSum = 0, memMax = 0;
            DateTimeOffset first = default, last = default;
            for (var i = 0; i < _count; i++)
            {
                var index = (_next - _count + i + _at.Length) % _at.Length;
                if (_at[index] < since)
                    continue;
                if (used == 0)
                {
                    first = _at[index];
                    cpuMax = _cpu[index];
                    memMax = _memMb[index];
                }

                cpuMax = Math.Max(cpuMax, _cpu[index]);
                memMax = Math.Max(memMax, _memMb[index]);
                cpuSum += _cpu[index];
                memSum += _memMb[index];
                last = _at[index];
                used++;
            }

            if (used == 0)
                return ResourceWindow.Empty;

            return new ResourceWindow(
                Math.Round(cpuSum / used, 1),
                Math.Round(cpuMax, 1),
                (int)Math.Min(int.MaxValue, (long)Math.Round((double)memSum / used)),
                (int)Math.Min(int.MaxValue, memMax),
                (int)Math.Round((last - first + _interval).TotalSeconds),
                used);
        }
    }

    internal static double? CpuPercent(SystemTimes previous, SystemTimes current)
    {
        // Kernel time from GetSystemTimes already includes idle time.
        var total = (current.Kernel - previous.Kernel) + (current.User - previous.User);
        var idle = current.Idle - previous.Idle;
        if (current.Kernel < previous.Kernel || current.User < previous.User || current.Idle < previous.Idle
            || total == 0 || idle > total)
            return null;
        return Math.Clamp((double)(total - idle) / total * 100d, 0d, 100d);
    }

    private static SystemTimes? ReadSystemTimes()
        => GetSystemTimes(out var idle, out var kernel, out var user)
            ? new SystemTimes(ToTicks(idle), ToTicks(kernel), ToTicks(user))
            : null;

    private static ulong ToTicks(FileTime value) => ((ulong)value.High << 32) | value.Low;

    internal readonly record struct SystemTimes(ulong Idle, ulong Kernel, ulong User);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low;
        public uint High;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out FileTime idle, out FileTime kernel, out FileTime user);
}

internal sealed record ResourceWindow(
    double? CpuAvgPct,
    double? CpuMaxPct,
    int? MemUsedAvgMb,
    int? MemUsedMaxMb,
    int SampleWindowSeconds,
    int SampleCount)
{
    internal static readonly ResourceWindow Empty = new(null, null, null, null, 0, 0);
}
