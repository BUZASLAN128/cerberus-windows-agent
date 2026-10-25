using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>
/// Reboot flag plus the cached Windows Update result. The search itself runs in <see cref="WindowsUpdateCache"/>;
/// this collector only reads the cache and never calls the searcher.
/// </summary>
internal sealed class UpdatesTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    internal const int MaxRecent = 20;

    private readonly IWindowsUpdateCacheReader _cache;
    private readonly Func<bool?> _rebootProbe;

    public UpdatesTelemetrySectionCollector()
        : this(WindowsUpdateCache.Shared, ReadRebootRequired)
    {
    }

    public UpdatesTelemetrySectionCollector(IWindowsUpdateCacheReader cache, Func<bool?> rebootProbe)
    {
        _cache = cache;
        _rebootProbe = rebootProbe;
    }

    public string SectionName => "updates";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
        => ValueTask.FromResult(Build(_rebootProbe(), _cache.TryGet()));

    internal static object Build(bool? rebootRequired, WindowsUpdateCacheEntry? cached)
    {
        var recent = (cached?.Scan.Recent ?? Array.Empty<WindowsUpdateEntry>())
            .OrderByDescending(e => e.InstalledUtc ?? DateTimeOffset.MinValue)
            .ThenBy(e => e.Title, StringComparer.Ordinal)
            .Select(e => new
            {
                kb = ServerFactText.CleanOrNull(e.Kb, 16),
                title = ServerFactText.Clean(e.Title, 160),
                installed_utc = ServerFactText.UtcOrNull(e.InstalledUtc),
            })
            .Distinct()
            .Take(MaxRecent)
            .ToArray();

        return new
        {
            status = "ok",
            reboot_required = rebootRequired,
            recent,
            pending = cached is null
                ? new { status = "unavailable", count = (int?)null, security_count = (int?)null, checked_at_utc = (string?)null }
                : new
                {
                    status = "ok",
                    count = (int?)cached.Scan.PendingCount,
                    security_count = (int?)cached.Scan.SecurityCount,
                    checked_at_utc = (string?)ServerFactText.Utc(cached.CheckedAt),
                },
        };
    }

    private static bool? ReadRebootRequired()
    {
        try
        {
            using var wu = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
            using var cbs = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");
            return wu is not null || cbs is not null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
        {
            return null;
        }
    }
}
