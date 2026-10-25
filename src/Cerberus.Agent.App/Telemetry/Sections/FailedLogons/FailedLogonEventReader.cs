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
/// classification are taken from the event XML; account-name fields are never read.
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

    internal static readonly string[] Channels = { Security, RdpCore, OpenSsh, Application, SystemLog };

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    private static string Query(string channel, long after) => channel switch
    {
        Security => $"*[System[(EventID=4625 or EventID=1102) and (EventRecordID > {after})]]",
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

    /// <summary>One scanned record: its id and the classified event (null when the record is not a failed logon).</summary>
    internal readonly record struct ScannedRecord(long? RecordId, FailedLogonEvent? Event);

    /// <param name="serviceLookup">Installed service names for the Application channel (null result = lookup failed); defaults to the live list.</param>
    public static ChannelRead Read(string channel, long after, CancellationToken ct, Func<HashSet<string>?>? serviceLookup = null)
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
            return Scan(channel, after, Records(reader, channel, sqlServices), ct: ct);
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

    private static IEnumerable<ScannedRecord> Records(EventLogReader reader, string channel, HashSet<string>? sqlServices)
    {
        while (true)
        {
            using var record = reader.ReadEvent();
            if (record is null)
                yield break;
            yield return new ScannedRecord(record.RecordId, Parse(channel, record, sqlServices));
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

    private static FailedLogonEvent? Parse(string channel, EventRecord record, HashSet<string>? sqlServices)
    {
        var time = record.TimeCreated is { } t ? new DateTimeOffset(t.ToUniversalTime(), TimeSpan.Zero) : DateTimeOffset.UtcNow;
        EventData data;
        try
        {
            data = ReadData(record.ToXml());
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or EventLogException)
        {
            return null;
        }

        switch (channel)
        {
            case SystemLog:
                return string.Equals(record.ProviderName, "Microsoft-Windows-Eventlog", StringComparison.OrdinalIgnoreCase)
                    ? new FailedLogonEvent(FailedLogonSource.LogCleared, time, null)
                    : null;
            case Security:
                if (record.Id == 1102)
                    return new FailedLogonEvent(FailedLogonSource.LogCleared, time, null);
                return new FailedLogonEvent(
                    FailedLogonSource.Security4625,
                    time,
                    data.Named.GetValueOrDefault("IpAddress"),
                    int.TryParse(data.Named.GetValueOrDefault("LogonType"), out var type) ? type : null,
                    data.Named.GetValueOrDefault("ProcessName"));
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
                // also be an installed SQL Server service. 18456 template: %1 account, %2 reason, %3 "[CLIENT: x]". The Application log accepts writes from
                // non-admin callers, so only the third data field is read: no scan of the other values. A failed
                // SQL logon without a usable address is still counted. (Not filtered by event UserId: the service
                // account differs per install and is not reliably known to the agent.)
                return new FailedLogonEvent(
                    FailedLogonSource.Sql18456,
                    time,
                    FailedLogonClassifier.SqlClientIpFromFields(data.Positional));
            default:
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
    /// classification; account-name fields are dropped from the named set.
    /// </summary>
    private static EventData ReadData(string xml)
    {
        var named = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var positional = new List<string>();
        var doc = XDocument.Parse(xml);
        foreach (var d in doc.Descendants(Ns + "Data"))
        {
            var name = (string?)d.Attribute("Name") ?? $"#{positional.Count}";
            positional.Add(d.Value);
            if (string.Equals(name, "TargetUserName", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "SubjectUserName", StringComparison.OrdinalIgnoreCase))
                continue;
            named[name] = d.Value;
        }
        return new EventData(named, positional);
    }
}
