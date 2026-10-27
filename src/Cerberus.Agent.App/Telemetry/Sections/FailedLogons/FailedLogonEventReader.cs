using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

internal sealed record ChannelRead(
    string Channel,
    IReadOnlyList<FailedLogonEvent> Events,
    long LastRecordId,
    bool Capped,
    bool Present,
    bool Failed);

/// <summary>
/// Reads failed-logon events from the Windows event channels by record id. Only the fields needed for
/// classification are taken from the event XML; account-name fields are never read, except for the user name and
/// domain of a successful interactive logon (4624).
/// </summary>
internal static class FailedLogonEventReader
{
    internal const int MaxEventsPerChannel = 20000;
    // Bounds records scanned per read, matching or not: a flood of rejected records cannot stall the section.
    internal const int MaxScannedPerChannel = 50000;
    internal const string Security = "Security";
    internal const string RdpCore = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
    internal const string OpenSsh = "OpenSSH/Operational";
    internal const string Application = "Application";
    internal const string SystemLog = "System";
    internal static readonly TimeSpan LogonLookback = TimeSpan.FromDays(7);
    // The time filter does not end a reverse scan early: a large log without recent logons is scanned to its start.
    internal static readonly TimeSpan LogonLookbackBudget = TimeSpan.FromSeconds(1.5);

    internal static readonly string[] Channels = { Security, RdpCore, OpenSsh, Application, SystemLog };

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    private static string Query(string channel, long after) => channel switch
    {
        // One pass over the Security log: failed logons, clears, privileged group changes and (only logon types 2 and
        // 10, filtered server side so network logons never use up the scan cap) successful logons.
        Security => $"*[(System[(EventID=4625 or EventID=1102 or EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757) and (EventRecordID > {after})]) "
            + $"or (System[(EventID=4624) and (EventRecordID > {after})] and EventData[Data[@Name='LogonType']=10 or Data[@Name='LogonType']=2])]",
        SystemLog => $"*[System[(EventID=104) and (EventRecordID > {after})]]",
        RdpCore => $"*[System[(EventID=140) and (EventRecordID > {after})]]",
        Application => $"*[System[(EventID=18456) and (EventRecordID > {after})]]",
        _ => $"*[System[(EventRecordID > {after})]]",
    };

    /// <summary>Oldest and newest record id in the channel (0 when empty); null when the channel is missing or unreadable.</summary>
    public static (long Oldest, long Newest)? Bounds(string channel, out bool present)
    {
        present = true;
        try
        {
            return (EdgeRecordId(channel, reverse: false), EdgeRecordId(channel, reverse: true));
        }
        catch (EventLogNotFoundException)
        {
            present = false;
            return null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
        {
            return null;
        }
    }

    private static long EdgeRecordId(string channel, bool reverse)
    {
        var query = new EventLogQuery(channel, PathType.LogName, "*") { ReverseDirection = reverse };
        using var reader = new EventLogReader(query);
        using var record = reader.ReadEvent();
        return record?.RecordId ?? 0;
    }

    /// <summary>
    /// Time of the newest Security 1102 still in the log (one reverse read, stops at the first hit). <c>Ok</c> is false
    /// when the log could not be read; <c>Time</c> is null when it was read and holds none.
    /// </summary>
    public static (bool Ok, DateTimeOffset? Time) LatestSecurityCleared(CancellationToken ct)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            using var reader = new EventLogReader(new EventLogQuery(Security, PathType.LogName, "*[System[(EventID=1102)]]") { ReverseDirection = true });
            using var record = reader.ReadEvent();
            return (true, record?.TimeCreated is { } t ? new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero) : null);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
        {
            return (false, null);
        }
    }

    /// <summary>
    /// Successful interactive logons (4624, type 2 or 10) of the last <see cref="LogonLookback"/> with a record id at or
    /// below <paramref name="upTo"/>, newest first, at most <paramref name="maxEvents"/>. After
    /// <see cref="LogonLookbackBudget"/> the read is cancelled and keeps what it found. Null when the log could not be read.
    /// </summary>
    public static IReadOnlyList<FailedLogonEvent>? ReadRecentLogons(long upTo, int maxEvents, CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(LogonLookbackBudget);
        try
        {
            // One match per native call: CancelReading drops the batch being filled, and with the default batch of 64
            // a sparse query would lose every match found before the budget ran out.
            using var reader = new EventLogReader(new EventLogQuery(Security, PathType.LogName, RecentLogonsQuery(upTo, LogonLookback)) { ReverseDirection = true })
            {
                BatchSize = 1,
            };
            using var cancel = budget.Token.Register(reader.CancelReading);
            return TakeNewest(Records(reader, Security, null, new SqlEventProvenance()), maxEvents, MaxScannedPerChannel, budget.Token, ct);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
        {
            return null;
        }
    }

    internal static string RecentLogonsQuery(long upTo, TimeSpan lookback)
        => $"*[System[(EventID=4624) and (EventRecordID <= {upTo}) and TimeCreated[timediff(@SystemTime) <= {(long)lookback.TotalMilliseconds}]] "
           + "and EventData[Data[@Name='LogonType']=10 or Data[@Name='LogonType']=2]]";

    /// <summary>
    /// Successful logons in input order until <paramref name="maxEvents"/> are found, <paramref name="maxScanned"/> records
    /// were scanned or <paramref name="budget"/> ran out; a read cancelled by the budget keeps what it found.
    /// </summary>
    internal static List<FailedLogonEvent> TakeNewest(IEnumerable<ScannedRecord> records, int maxEvents, int maxScanned, CancellationToken budget, CancellationToken ct)
    {
        var events = new List<FailedLogonEvent>();
        var scanned = 0;
        try
        {
            foreach (var record in records)
            {
                ct.ThrowIfCancellationRequested();
                if (budget.IsCancellationRequested || events.Count >= maxEvents || scanned >= maxScanned)
                    break;
                scanned++;
                if (record.Event is { Source: FailedLogonSource.SuccessfulLogon4624 } logon)
                    events.Add(logon);
            }
        }
        catch (Exception ex) when ((ex is OperationCanceledException or EventLogException) && budget.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            // The budget cancelled the native read (CancelReading); the logons found so far stay valid.
        }
        return events;
    }

    /// <summary>One scanned record: its id and the classified event (null when the record is not a failed logon).</summary>
    internal readonly record struct ScannedRecord(long? RecordId, FailedLogonEvent? Event);

    /// <param name="serviceLookup">Installed service names for the Application channel (null result = lookup failed); defaults to the live list.</param>
    /// <param name="processLookup">SQL service name to its running process id and start time (null result = unknown); defaults to the live lookup.</param>
    public static ChannelRead Read(string channel, long after, CancellationToken ct, Func<HashSet<string>?>? serviceLookup = null,
        Func<string, (int ProcessId, DateTimeOffset StartUtc)?>? processLookup = null)
    {
        try
        {
            // Application-log providers are only trusted when the matching SQL Server service is installed. When the
            // service list cannot be read the channel fails (cursor untouched) instead of silently dropping SQL events.
            HashSet<string>? sqlServices = null;
            if (channel == Application)
            {
                sqlServices = (serviceLookup ?? FailedLogonProtocolProbe.TryReadServiceNames)();
                if (sqlServices is null)
                    return new ChannelRead(channel, Array.Empty<FailedLogonEvent>(), after, false, Present: true, Failed: true);
            }
            using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName, Query(channel, after)));
            return Scan(channel, after, Records(reader, channel, sqlServices, new SqlEventProvenance(processLookup)), ct: ct);
        }
        catch (EventLogNotFoundException)
        {
            return new ChannelRead(channel, Array.Empty<FailedLogonEvent>(), after, false, Present: false, Failed: false);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or EventLogException)
        {
            return new ChannelRead(channel, Array.Empty<FailedLogonEvent>(), after, false, Present: true, Failed: true);
        }
    }

    private static IEnumerable<ScannedRecord> Records(EventLogReader reader, string channel, HashSet<string>? sqlServices, SqlEventProvenance provenance)
    {
        while (true)
        {
            using var record = reader.ReadEvent();
            if (record is null)
                yield break;
            yield return new ScannedRecord(record.RecordId, Parse(channel, record, sqlServices, provenance));
        }
    }

    /// <summary>
    /// Walks records in id order. Stops, marked capped, after <paramref name="maxEvents"/> accepted events or
    /// <paramref name="maxScanned"/> scanned records of any kind; the returned position is then the last scanned
    /// record, so the next window continues right behind it even when none of the scanned records matched.
    /// </summary>
    internal static ChannelRead Scan(
        string channel,
        long after,
        IEnumerable<ScannedRecord> records,
        int maxEvents = MaxEventsPerChannel,
        int maxScanned = MaxScannedPerChannel,
        CancellationToken ct = default)
    {
        var events = new List<FailedLogonEvent>();
        var last = after;
        var scanned = 0;
        var capped = false;
        foreach (var record in records)
        {
            ct.ThrowIfCancellationRequested();
            if (events.Count >= maxEvents || scanned >= maxScanned)
            {
                capped = true;
                break;
            }
            scanned++;
            if (record.RecordId is { } id && id > last)
                last = id;
            if (record.Event is not null)
                events.Add(record.Event);
        }
        return new ChannelRead(channel, events, last, capped, Present: true, Failed: false);
    }

    private static FailedLogonEvent? Parse(string channel, EventRecord record, HashSet<string>? sqlServices, SqlEventProvenance provenance)
    {
        var time = record.TimeCreated is { } t ? new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero) : DateTimeOffset.UtcNow;
        EventData data;
        string xml;
        try
        {
            xml = record.ToXml();
            // Account names are read only for successful interactive logons; failed attempts never expose them.
            data = ReadData(xml, keepAccountNames: channel == Security && record.Id == 4624);
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or EventLogException)
        {
            return null;
        }

        switch (channel)
        {
            case SystemLog:
                return SystemLogCleared(record.ProviderName, xml, time);
            case Security:
                switch (record.Id)
                {
                    case 1102:
                        return new FailedLogonEvent(FailedLogonSource.LogCleared, time, null);
                    case 4625:
                        return new FailedLogonEvent(
                            FailedLogonSource.Security4625,
                            time,
                            data.Named.GetValueOrDefault("IpAddress"),
                            int.TryParse(data.Named.GetValueOrDefault("LogonType"), out var type) ? type : null,
                            data.Named.GetValueOrDefault("ProcessName"));
                    case 4624:
                        return SecurityLogEventParser.Logon(time, data.Named);
                    default:
                        return SecurityLogEventParser.GroupChange(record.Id, time, data.Named);
                }
            case RdpCore:
                // Fixed manifest field only: no scan of other values.
                return new FailedLogonEvent(FailedLogonSource.RdpCore140, time, data.Named.GetValueOrDefault("IPString"));
            case OpenSsh:
                foreach (var value in data.Positional)
                    if (FailedLogonClassifier.ParseSshFailedIp(value) is { } sshIp)
                        return new FailedLogonEvent(FailedLogonSource.OpenSsh, time, sshIp);
                return null;
            case Application:
                if (!IsInstalledSqlProvider(record.ProviderName, sqlServices))
                    return null;
                // Any local user can write Application events under an MSSQL provider name, so the provider must
                // also be an installed SQL Server service and the writer process must be that service (see
                // SqlEventProvenance); other events are only counted as unverified. 18456 template: %1 account, %2 reason,
                // %3 "[CLIENT: x]". The Application log accepts writes from non-admin callers, so only the third data
                // field is read: no scan of the other values. A failed SQL logon without a usable address is still counted.
                return provenance.Classify(record.ProviderName!, record.ProcessId, time, data.Positional);
            default:
                return null;
        }
    }

    /// <summary>
    /// System 104 names the cleared channel in <c>UserData/LogFileCleared/Channel</c>. Clearing a channel the agent does
    /// not read is not a gap; when the channel cannot be read the event still counts, so a gap is signalled rather than missed.
    /// </summary>
    internal static FailedLogonEvent? SystemLogCleared(string? provider, string xml, DateTimeOffset time)
    {
        if (!string.Equals(provider, "Microsoft-Windows-Eventlog", StringComparison.OrdinalIgnoreCase))
            return null;
        var channel = ClearedChannel(xml);
        if (channel is not null && !Channels.Contains(channel, StringComparer.OrdinalIgnoreCase))
            return null;
        return new FailedLogonEvent(FailedLogonSource.LogCleared, time, null);
    }

    private static string? ClearedChannel(string xml)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            var value = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Channel" && e.Parent?.Name.LocalName == "LogFileCleared")?.Value
                        ?? doc.Descendants(Ns + "Data").FirstOrDefault(d => string.Equals((string?)d.Attribute("Name"), "Channel", StringComparison.OrdinalIgnoreCase))?.Value;
            return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        }
        catch (System.Xml.XmlException)
        {
            return null;
        }
    }

    internal static bool IsSqlProvider(string? provider)
        => string.Equals(provider, "MSSQLSERVER", StringComparison.OrdinalIgnoreCase)
           || (provider is not null && provider.StartsWith("MSSQL$", StringComparison.OrdinalIgnoreCase));

    /// <summary>A SQL provider name that matches an installed service (MSSQLSERVER, MSSQL$name).</summary>
    internal static bool IsInstalledSqlProvider(string? provider, IReadOnlySet<string>? installedServices)
        => provider is not null && installedServices is not null && IsSqlProvider(provider) && installedServices.Contains(provider);

    private sealed record EventData(Dictionary<string, string> Named, List<string> Positional);

    /// <summary>
    /// Event data values by name (unnamed values get "#n") and in template order. Values stay in memory only for
    /// classification; account-name fields are dropped from the named set unless <paramref name="keepAccountNames"/>.
    /// </summary>
    private static EventData ReadData(string xml, bool keepAccountNames = false)
    {
        var named = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var positional = new List<string>();
        var doc = XDocument.Parse(xml);
        foreach (var d in doc.Descendants(Ns + "Data"))
        {
            var name = (string?)d.Attribute("Name") ?? $"#{positional.Count}";
            positional.Add(d.Value);
            if (!keepAccountNames
                && (string.Equals(name, "TargetUserName", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(name, "SubjectUserName", StringComparison.OrdinalIgnoreCase)))
                continue;
            named[name] = d.Value;
        }
        return new EventData(named, positional);
    }
}
