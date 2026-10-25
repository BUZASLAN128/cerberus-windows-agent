using System.Text.RegularExpressions;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Telemetry;

internal sealed record WindowsUpdateEntry(string? Kb, string Title, DateTimeOffset? InstalledUtc);

internal sealed record WindowsUpdateScan(int PendingCount, int SecurityCount, IReadOnlyList<WindowsUpdateEntry> Recent);

internal sealed record WindowsUpdateCacheEntry(WindowsUpdateScan Scan, DateTimeOffset CheckedAt);

internal interface IWindowsUpdateSearcher
{
    Task<WindowsUpdateScan> SearchAsync(CancellationToken ct);
}

internal interface IWindowsUpdateCacheReader
{
    /// <summary>The last completed search, or null when none completed or it is older than the TTL.</summary>
    WindowsUpdateCacheEntry? TryGet();
}

/// <summary>
/// Background Windows Update search result. Snapshot and collect_facts only read it; the search never runs
/// inline. Start() is called by the service host (server profile only).
/// </summary>
internal sealed class WindowsUpdateCache : IWindowsUpdateCacheReader, IDisposable
{
    internal static readonly TimeSpan SearchTimeout = TimeSpan.FromSeconds(60);
    internal static readonly TimeSpan Ttl = TimeSpan.FromHours(2);
    internal static readonly TimeSpan RefreshAfter = TimeSpan.FromMinutes(50);
    internal static readonly TimeSpan RetryAfterFailure = TimeSpan.FromMinutes(5);

    public static WindowsUpdateCache Shared { get; } = new(new ComWindowsUpdateSearcher(), TimeProvider.System);

    private readonly IWindowsUpdateSearcher _searcher;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private WindowsUpdateCacheEntry? _entry;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private Task? _inFlight;
    private bool _skipLogged;
    private IAgentLogger _log;

    public WindowsUpdateCache(IWindowsUpdateSearcher searcher, TimeProvider time, IAgentLogger? log = null)
    {
        _searcher = searcher;
        _time = time;
        _log = log ?? NullAgentLogger.Instance;
    }

    public WindowsUpdateCacheEntry? TryGet()
    {
        lock (_gate)
        {
            return _entry is { } entry && _time.GetUtcNow() - entry.CheckedAt <= Ttl ? entry : null;
        }
    }

    public void Start(IAgentLogger? log = null)
    {
        lock (_gate)
        {
            if (_cts is not null)
                return;
            if (log is not null)
                _log = log;
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _loop = Task.Run(() => RunAsync(token));
        }
    }

    /// <summary>
    /// One search bounded by the 60 s timeout. Returns false on timeout, failure, or when the previous search is still
    /// running (the COM call ignores cancellation, so a timed-out search is never followed by a second one until it
    /// ends). The old entry is kept until its TTL.
    /// </summary>
    internal async Task<bool> RefreshAsync(CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task<WindowsUpdateScan>? started = null;
        var logSkip = false;
        lock (_gate)
        {
            if (_inFlight is { IsCompleted: false })
            {
                logSkip = !_skipLogged;
                _skipLogged = true;
            }
            else
            {
                _skipLogged = false;
                _inFlight = started = Task.Run(() => _searcher.SearchAsync(linked.Token), CancellationToken.None);
            }
        }

        if (started is null)
        {
            if (logSkip)
                _log.Warn("Windows Update search skipped: the previous search is still running.");
            return false;
        }

        var search = started;
        try
        {
            var timeout = Task.Delay(SearchTimeout, _time, delayCts.Token);
            if (await Task.WhenAny(search, timeout).ConfigureAwait(false) != search)
            {
                ct.ThrowIfCancellationRequested();
                linked.Cancel();
                _ = search.ContinueWith(static t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
                return false;
            }

            delayCts.Cancel();
            var scan = await search.ConfigureAwait(false);
            lock (_gate)
                _entry = new WindowsUpdateCacheEntry(scan, _time.GetUtcNow());
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var ok = await RefreshAsync(ct).ConfigureAwait(false);
                await Task.Delay(ok ? RefreshAfter : RetryAfterFailure, _time, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    public void Dispose()
    {
        CancellationTokenSource? cts;
        lock (_gate)
        {
            cts = _cts;
            _cts = null;
        }

        cts?.Cancel();
        cts?.Dispose();
    }
}

/// <summary>Windows Update Agent through the in-box COM API, late bound. Search only; nothing is downloaded or installed.</summary>
internal sealed partial class ComWindowsUpdateSearcher : IWindowsUpdateSearcher
{
    private const string SecurityUpdatesCategoryId = "0fa1201d-4330-4fa8-8ae9-b877473b6441";
    private const int MaxHistoryEntries = 200;
    private const int MaxRecent = 20;

    public Task<WindowsUpdateScan> SearchAsync(CancellationToken ct) => Task.Run(() => Search(ct), ct);

    private static WindowsUpdateScan Search(CancellationToken ct)
    {
        var type = Type.GetTypeFromProgID("Microsoft.Update.Session")
            ?? throw new PlatformNotSupportedException("Windows Update Agent is not available.");
        dynamic session = Activator.CreateInstance(type)!;
        dynamic searcher = session.CreateUpdateSearcher();
        searcher.Online = false;

        dynamic found = searcher.Search("IsInstalled=0 and IsHidden=0");
        dynamic updates = found.Updates;
        int pending = updates.Count, security = 0;
        for (var i = 0; i < pending; i++)
        {
            ct.ThrowIfCancellationRequested();
            dynamic categories = updates.Item(i).Categories;
            int categoryCount = categories.Count;
            for (var j = 0; j < categoryCount; j++)
            {
                string id = categories.Item(j).CategoryID;
                if (string.Equals(id, SecurityUpdatesCategoryId, StringComparison.OrdinalIgnoreCase))
                {
                    security++;
                    break;
                }
            }
        }

        var recent = new List<WindowsUpdateEntry>();
        int total = searcher.GetTotalHistoryCount();
        if (total > 0)
        {
            dynamic history = searcher.QueryHistory(0, Math.Min(total, MaxHistoryEntries));
            int historyCount = history.Count;
            for (var i = 0; i < historyCount; i++)
            {
                ct.ThrowIfCancellationRequested();
                dynamic entry = history.Item(i);
                // Operation 1 = installation, ResultCode 2 = succeeded.
                if ((int)entry.Operation != 1 || (int)entry.ResultCode != 2)
                    continue;
                string title = entry.Title ?? string.Empty;
                DateTime date = entry.Date;
                var match = KbPattern().Match(title);
                recent.Add(new WindowsUpdateEntry(
                    match.Success ? match.Value.ToUpperInvariant() : null,
                    title,
                    new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc))));
            }
        }

        return new WindowsUpdateScan(
            pending,
            security,
            recent.OrderByDescending(e => e.InstalledUtc).Take(MaxRecent).ToArray());
    }

    [GeneratedRegex(@"KB\d{4,8}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex KbPattern();
}
