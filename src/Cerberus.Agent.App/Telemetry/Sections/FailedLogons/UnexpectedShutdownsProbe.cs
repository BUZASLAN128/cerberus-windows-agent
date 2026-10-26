using System.Diagnostics.Eventing.Reader;

namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

internal sealed record UnexpectedShutdowns(int Count7d, DateTimeOffset? LastUtc);

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

    /// <exception cref="EventLogException">The System log could not be queried.</exception>
    public static UnexpectedShutdowns Read(CancellationToken ct)
    {
        var times = new List<DateTimeOffset>();
        using var reader = new EventLogReader(new EventLogQuery(FailedLogonEventReader.SystemLog, PathType.LogName, Query) { ReverseDirection = true });
        while (times.Count < MaxEventsRead)
        {
            ct.ThrowIfCancellationRequested();
            using var record = reader.ReadEvent();
            if (record is null)
                break;
            if (record.TimeCreated is { } t && IsExpectedProvider(record.Id, record.ProviderName))
                times.Add(new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero));
        }
        return Summarize(times);
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
