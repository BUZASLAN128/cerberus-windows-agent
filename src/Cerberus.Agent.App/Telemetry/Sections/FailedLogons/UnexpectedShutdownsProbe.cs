using System.Diagnostics.Eventing.Reader;

namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

/// <param name="Truncated">More than <see cref="UnexpectedShutdownsProbe.MaxEventsRead"/> matching events exist in the window, so the count is a lower bound.</param>
internal sealed record UnexpectedShutdowns(int Count7d, DateTimeOffset? LastUtc, bool Truncated = false);

/// <summary>
/// System log events 41 (Kernel-Power) and 6008 (EventLog) of the last 7 days: a bounded, newest-first time-window
/// query that needs no cursor. One crash writes both events at the next boot, so records within
/// <see cref="SameIncident"/> of the previously counted one belong to the same shutdown.
/// </summary>
internal static class UnexpectedShutdownsProbe
{
    internal const int MaxEventsRead = 200;
    internal static readonly TimeSpan SameIncident = TimeSpan.FromMinutes(5);
    private const string Query = "*[System[(EventID=41 or EventID=6008) and TimeCreated[timediff(@SystemTime) <= 604800000]]]";

    private static readonly TimeSpan Window = TimeSpan.FromDays(7);
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(1);
    private static readonly TimeSpan BootTolerance = TimeSpan.FromMinutes(1);
    private static readonly object CacheGate = new();
    private static DateTimeOffset? _cachedBoot;
    private static DateTimeOffset _cachedAt;
    private static IReadOnlyList<DateTimeOffset> _cachedTimes = Array.Empty<DateTimeOffset>();

    /// <exception cref="EventLogException">The System log could not be queried.</exception>
    public static UnexpectedShutdowns Read(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var boot = now - TimeSpan.FromMilliseconds(Environment.TickCount64);
        return ReadCached(now, boot, () => ReadTimes(ct));
    }

    /// <summary>
    /// Both events are written at boot, so the 7-day event list only changes with a new boot. The list is reused for
    /// the same boot time within <see cref="CacheTtl"/> (which also bounds the effect of a log clear) and the window is
    /// re-applied on every call; a failed fetch is not cached.
    /// </summary>
    internal static UnexpectedShutdowns ReadCached(DateTimeOffset now, DateTimeOffset bootUtc, Func<IReadOnlyList<DateTimeOffset>> fetch)
    {
        IReadOnlyList<DateTimeOffset> times;
        lock (CacheGate)
        {
            if (_cachedBoot is { } cached && (bootUtc - cached).Duration() <= BootTolerance && now >= _cachedAt && now - _cachedAt <= CacheTtl)
            {
                times = _cachedTimes;
            }
            else
            {
                times = fetch();
                _cachedBoot = bootUtc;
                _cachedAt = now;
                _cachedTimes = times;
            }
        }
        // The fetch reads one matching event past the cap: seeing it inside the window means the older ones were not counted.
        var inWindow = times.Where(t => now - t <= Window).OrderByDescending(t => t).ToList();
        return Summarize(inWindow.Take(MaxEventsRead)) with { Truncated = inWindow.Count > MaxEventsRead };
    }

    internal static void ResetCache()
    {
        lock (CacheGate)
        {
            _cachedBoot = null;
            _cachedTimes = Array.Empty<DateTimeOffset>();
        }
    }

    private static List<DateTimeOffset> ReadTimes(CancellationToken ct)
    {
        var times = new List<DateTimeOffset>();
        using var reader = new EventLogReader(new EventLogQuery(FailedLogonEventReader.SystemLog, PathType.LogName, Query) { ReverseDirection = true });
        while (times.Count <= MaxEventsRead)
        {
            ct.ThrowIfCancellationRequested();
            using var record = reader.ReadEvent();
            if (record is null)
                break;
            if (record.TimeCreated is { } t && IsExpectedProvider(record.Id, record.ProviderName))
                times.Add(new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero));
        }
        return times;
    }

    internal static bool IsExpectedProvider(int eventId, string? provider) => eventId switch
    {
        41 => string.Equals(provider, "Microsoft-Windows-Kernel-Power", StringComparison.OrdinalIgnoreCase),
        6008 => string.Equals(provider, "EventLog", StringComparison.OrdinalIgnoreCase),
        _ => false,
    };

    /// <summary>Counts incidents (not raw events) and returns the newest time; input order does not matter.</summary>
    internal static UnexpectedShutdowns Summarize(IEnumerable<DateTimeOffset> eventTimes)
    {
        var count = 0;
        DateTimeOffset? last = null;
        DateTimeOffset? lastCounted = null;
        foreach (var t in eventTimes.OrderByDescending(x => x))
        {
            last ??= t;
            if (lastCounted is { } prev && prev - t <= SameIncident)
                continue;
            count++;
            lastCounted = t;
        }
        return new UnexpectedShutdowns(count, last);
    }
}
