using System.Runtime.InteropServices;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>Interactive and remote sessions with a user. Client names and addresses are never read.</summary>
internal sealed class SessionsTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    internal const int MaxSessions = 64;
    internal const int MaxUserLength = 104;

    internal sealed record RawSession(string? Domain, string? UserName, string State, string Kind, DateTimeOffset? LogonTime);

    public string SectionName => "sessions";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
        => ValueTask.FromResult(Build(SessionsNative.Read(ct)));

    internal static object Build(IEnumerable<RawSession> raw)
    {
        var sessions = raw
            .Select(s => new
            {
                user = ServerFactText.Clean(string.IsNullOrWhiteSpace(s.Domain) ? s.UserName : $"{s.Domain}\\{s.UserName}", MaxUserLength),
                state = s.State,
                kind = s.Kind,
                logon_time_utc = ServerFactText.UtcOrNull(s.LogonTime),
            })
            .Where(s => s.user.Length > 0)
            .OrderBy(s => s.user, StringComparer.OrdinalIgnoreCase)
            .ThenBy(s => s.user, StringComparer.Ordinal)
            .ThenBy(s => s.kind, StringComparer.Ordinal)
            .ThenBy(s => s.state, StringComparer.Ordinal)
            .ThenBy(s => s.logon_time_utc, StringComparer.Ordinal)
            .ToArray();

        return new
        {
            status = "ok",
            session_count = sessions.Length,
            active_count = sessions.Count(s => s.state == "active"),
            disconnected_count = sessions.Count(s => s.state == "disconnected"),
            truncated = sessions.Length > MaxSessions,
            sessions = sessions.Take(MaxSessions).ToArray(),
        };
    }
}

internal static class SessionsNative
{
    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;
    private const int WtsClientProtocolType = 16;
    private const int WtsSessionInfo = 24;

    public static IReadOnlyList<SessionsTelemetrySectionCollector.RawSession> Read(CancellationToken ct)
    {
        var result = new List<SessionsTelemetrySectionCollector.RawSession>();
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out var table, out var count))
            return result;

        try
        {
            var size = Marshal.SizeOf<WtsSessionEntry>();
            for (var i = 0; i < count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var entry = Marshal.PtrToStructure<WtsSessionEntry>(IntPtr.Add(table, i * size));
                var user = QueryString(entry.SessionId, WtsUserName);
                if (string.IsNullOrWhiteSpace(user))
                    continue;

                result.Add(new SessionsTelemetrySectionCollector.RawSession(
                    QueryString(entry.SessionId, WtsDomainName),
                    user,
                    MapState(entry.State),
                    MapKind(QueryProtocol(entry.SessionId)),
                    QueryLogonTime(entry.SessionId)));
            }
        }
        finally
        {
            WTSFreeMemory(table);
        }

        return result;
    }

    internal static string MapState(int state) => state switch
    {
        0 => "active",
        4 => "disconnected",
        5 => "idle",
        _ => "other",
    };

    internal static string MapKind(int protocol) => protocol switch
    {
        0 => "console",
        2 => "rdp",
        _ => "other",
    };

    private static string? QueryString(int sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, infoClass, out var buffer, out _))
            return null;
        try { return Marshal.PtrToStringUni(buffer); }
        finally { WTSFreeMemory(buffer); }
    }

    private static int QueryProtocol(int sessionId)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, WtsClientProtocolType, out var buffer, out var bytes))
            return -1;
        try { return bytes >= 2 ? Marshal.ReadInt16(buffer) : -1; }
        finally { WTSFreeMemory(buffer); }
    }

    private static DateTimeOffset? QueryLogonTime(int sessionId)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, WtsSessionInfo, out var buffer, out var bytes))
            return null;
        try
        {
            if (bytes < Marshal.SizeOf<WtsInfo>())
                return null;
            var info = Marshal.PtrToStructure<WtsInfo>(buffer);
            if (info.LogonTime <= 0)
                return null;
            return new DateTimeOffset(DateTime.FromFileTimeUtc(info.LogonTime), TimeSpan.Zero);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionEntry
    {
        public int SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsInfo
    {
        public int State;
        public int SessionId;
        public int IncomingBytes;
        public int OutgoingBytes;
        public int IncomingFrames;
        public int OutgoingFrames;
        public int IncomingCompressedBytes;
        public int OutgoingCompressedBytes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string WinStationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string Domain;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
        public long ConnectTime;
        public long DisconnectTime;
        public long LastInputTime;
        public long LogonTime;
        public long CurrentTime;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}
