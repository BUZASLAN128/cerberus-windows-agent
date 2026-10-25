using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

internal enum FailedLogonSource
{
    /// <summary>Security log event 4625.</summary>
    Security4625,
    /// <summary>RdpCoreTS/Operational event 140 (NLA credential failure with client address).</summary>
    RdpCore140,
    /// <summary>OpenSSH/Operational sshd failure line.</summary>
    OpenSsh,
    /// <summary>Application log event 18456 from a SQL Server provider.</summary>
    Sql18456,
    /// <summary>Security 1102 / System 104: an event log was cleared. Not an attempt; only marks the window as having a gap.</summary>
    LogCleared,
}

/// <summary>
/// One parsed failed-logon event. Deliberately has no account-name field: user names (often mistyped passwords)
/// are never read out of the event, only the protocol hints, source address and time.
/// </summary>
internal sealed record FailedLogonEvent(
    FailedLogonSource Source,
    DateTimeOffset TimeUtc,
    string? SourceIp,
    int? LogonType = null,
    string? ProcessName = null);

internal sealed record FailedLogonGroup(string Protocol, string SourceIp, int Count, DateTimeOffset FirstSeenUtc, DateTimeOffset LastSeenUtc);

internal sealed record FailedLogonTally(
    IReadOnlyDictionary<string, int> Counts,
    IReadOnlyList<FailedLogonGroup> Groups);

/// <summary>
/// Pure classification and aggregation of failed-logon events.
/// <para>
/// Primary-per-attempt rule: Security 4625 is the primary record of an attempt. A secondary record (RdpCoreTS 140,
/// OpenSSH log line) of the same attempt, same address (or the 4625 has none) within <see cref="CorrelationWindow"/>,
/// is consumed by the 4625 and not counted again. Secondary records without a matching 4625 count on their own.
/// 4625 classification: sshd process -> ssh; logon type 10 or termsrv process -> rdp; logon type 3 -> rdp only when
/// an RdpCoreTS 140 matches (NLA), otherwise other; everything else -> other.
/// </para>
/// </summary>
internal static partial class FailedLogonClassifier
{
    internal static readonly TimeSpan CorrelationWindow = TimeSpan.FromSeconds(10);
    internal const int GroupCap = 20;
    internal static readonly string[] Protocols = { "rdp", "ssh", "sql", "other" };

    [GeneratedRegex(@"\bFailed\s+[\w\-/]+\s+for\s+(?:invalid\s+user\s+)?.+\s+from\s+(\S+)\s+port\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SshFailedRegex();

    [GeneratedRegex(@"\[CLIENT:\s*([^\]\s]+)\s*\]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SqlClientRegex();

    /// <summary>
    /// Source address of an sshd "Failed password/publickey/..." line. "Invalid user" and "authentication failure"
    /// lines belong to the same attempt as the "Failed" line and are not counted again. Returns null otherwise.
    /// </summary>
    internal static string? ParseSshFailedIp(string? text)
    {
        if (string.IsNullOrEmpty(text) || text.Length > 4096)
            return null;
        var m = SshFailedRegex().Match(text);
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>Client address of a SQL Server 18456 text ("[CLIENT: x]"); null when absent.</summary>
    internal static string? ParseSqlClientIp(string? text)
    {
        if (string.IsNullOrEmpty(text) || text.Length > 4096)
            return null;
        var m = SqlClientRegex().Match(text);
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>
    /// Client address of an 18456 event from its fixed third data field (%3, "[CLIENT: x]"). The other fields carry the
    /// account name and reason, which a caller writing to the Application log controls, so they are never scanned.
    /// </summary>
    internal static string? SqlClientIpFromFields(IReadOnlyList<string> fields)
        => ParseSqlClientIp(fields.Count > 2 ? fields[2] : null);

    /// <summary>Canonical address text, or null for missing, unparsable, loopback and unspecified addresses.</summary>
    internal static string? NormalizeIp(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var text = raw.Trim();
        var scope = text.IndexOf('%');
        if (scope >= 0)
            text = text[..scope];
        if (text.Length > 45 || !IPAddress.TryParse(text, out var ip))
            return null;
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.None))
            return null;
        if (ip.AddressFamily != AddressFamily.InterNetwork && ip.AddressFamily != AddressFamily.InterNetworkV6)
            return null;
        return ip.ToString();
    }

    internal static string LeafName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return string.Empty;
        var i = path.LastIndexOfAny(new[] { '\\', '/' });
        return (i >= 0 ? path[(i + 1)..] : path).Trim().ToLowerInvariant();
    }

    internal static FailedLogonTally Tally(IEnumerable<FailedLogonEvent> events)
    {
        var security = new List<FailedLogonEvent>();
        var rdpPool = new List<FailedLogonEvent>();
        var sshPool = new List<FailedLogonEvent>();
        var direct = new List<(string Protocol, FailedLogonEvent Event)>();
        foreach (var e in events)
        {
            switch (e.Source)
            {
                case FailedLogonSource.Security4625: security.Add(e); break;
                case FailedLogonSource.RdpCore140: rdpPool.Add(e); break;
                case FailedLogonSource.OpenSsh: sshPool.Add(e); break;
                case FailedLogonSource.Sql18456: direct.Add(("sql", e)); break;
            }
        }

        var rdp = new TimePool(rdpPool);
        var ssh = new TimePool(sshPool);
        var resolved = new List<(string Protocol, string? Ip, DateTimeOffset Time)>();
        foreach (var e in security.OrderBy(x => x.TimeUtc))
        {
            var ip = NormalizeIp(e.SourceIp);
            var process = LeafName(e.ProcessName);
            if (process.StartsWith("sshd", StringComparison.Ordinal))
            {
                var hit = ssh.Consume(e.TimeUtc, ip);
                resolved.Add(("ssh", ip ?? NormalizeIp(hit?.SourceIp), e.TimeUtc));
            }
            else if (e.LogonType == 10 || process == "termsrv.exe")
            {
                var hit = rdp.Consume(e.TimeUtc, ip);
                resolved.Add(("rdp", ip ?? NormalizeIp(hit?.SourceIp), e.TimeUtc));
            }
            else if (e.LogonType == 3)
            {
                var hit = rdp.Consume(e.TimeUtc, ip);
                resolved.Add((hit is null ? "other" : "rdp", ip ?? NormalizeIp(hit?.SourceIp), e.TimeUtc));
            }
            else
            {
                resolved.Add(("other", ip, e.TimeUtc));
            }
        }

        foreach (var e in rdp.Unconsumed())
            resolved.Add(("rdp", NormalizeIp(e.SourceIp), e.TimeUtc));
        foreach (var e in ssh.Unconsumed())
            resolved.Add(("ssh", NormalizeIp(e.SourceIp), e.TimeUtc));
        foreach (var (protocol, e) in direct)
            resolved.Add((protocol, NormalizeIp(e.SourceIp), e.TimeUtc));

        var counts = Protocols.ToDictionary(p => p, _ => 0, StringComparer.Ordinal);
        var groups = new Dictionary<(string, string), (int Count, DateTimeOffset First, DateTimeOffset Last)>();
        foreach (var (protocol, ip, time) in resolved)
        {
            counts[protocol]++;
            if (ip is null)
                continue;
            var key = (protocol, ip);
            groups[key] = groups.TryGetValue(key, out var g)
                ? (g.Count + 1, time < g.First ? time : g.First, time > g.Last ? time : g.Last)
                : (1, time, time);
        }

        var list = groups
            .Select(kv => new FailedLogonGroup(kv.Key.Item1, kv.Key.Item2, kv.Value.Count, kv.Value.First, kv.Value.Last))
            .OrderByDescending(g => g.Count)
            .ThenByDescending(g => g.LastSeenUtc)
            .ThenBy(g => g.Protocol, StringComparer.Ordinal)
            .ThenBy(g => g.SourceIp, StringComparer.Ordinal)
            .ToList();
        return new FailedLogonTally(counts, list);
    }

    /// <summary>Time-sorted secondary records; each can be consumed once by a primary record within the window.</summary>
    private sealed class TimePool
    {
        private readonly FailedLogonEvent[] _items;
        private readonly bool[] _used;
        private readonly int[] _skip;

        public TimePool(List<FailedLogonEvent> items)
        {
            _items = items.OrderBy(i => i.TimeUtc).ToArray();
            _used = new bool[_items.Length];
            _skip = Enumerable.Range(0, _items.Length + 1).ToArray();
        }

        /// <summary>Consumes and returns an unused record within the window; same address when <paramref name="ip"/> is known.</summary>
        public FailedLogonEvent? Consume(DateTimeOffset time, string? ip)
        {
            var from = time - CorrelationWindow;
            var to = time + CorrelationWindow;
            var lo = 0;
            var hi = _items.Length;
            while (lo < hi)
            {
                var mid = (lo + hi) / 2;
                if (_items[mid].TimeUtc < from) lo = mid + 1; else hi = mid;
            }

            var i = Next(lo);
            var scanned = 0;
            while (i < _items.Length && _items[i].TimeUtc <= to && scanned++ < 4096)
            {
                if (ip is null || NormalizeIp(_items[i].SourceIp) == ip)
                {
                    _used[i] = true;
                    _skip[i] = i + 1;
                    return _items[i];
                }
                i = Next(i + 1);
            }
            return null;
        }

        public IEnumerable<FailedLogonEvent> Unconsumed()
        {
            for (var i = 0; i < _items.Length; i++)
                if (!_used[i])
                    yield return _items[i];
        }

        private int Next(int i)
        {
            var root = i;
            while (_skip[root] != root)
                root = _skip[root];
            while (_skip[i] != root)
            {
                var next = _skip[i];
                _skip[i] = root;
                i = next;
            }
            return root;
        }
    }
}
