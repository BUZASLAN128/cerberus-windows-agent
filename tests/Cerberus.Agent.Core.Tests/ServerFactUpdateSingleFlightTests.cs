using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class ServerFactSectionsTests
{
    // ---- Windows Update cache: one search at a time ----------------------------------------------------------

    private sealed class RecordingLogger : IAgentLogger
    {
        private readonly List<string> _warnings = new();

        public string[] Warnings
        {
            get
            {
                lock (_warnings)
                    return _warnings.ToArray();
            }
        }

        public void Info(string message) { }

        public void Warn(string message)
        {
            lock (_warnings)
                _warnings.Add(message);
        }

        public void Error(string message, Exception? ex = null) { }
    }

    [Fact]
    public async Task UpdateCache_TimedOutSearchIsNotFollowedByAnotherUntilItEnds()
    {
        var time = new ManualTimeProvider(T0);
        var block = new TaskCompletionSource<WindowsUpdateScan>();
        var searcher = new FakeUpdateSearcher(_ => block.Task);
        var log = new RecordingLogger();
        using var cache = new WindowsUpdateCache(searcher, time, log);

        var first = cache.RefreshAsync(CancellationToken.None);
        Assert.True(await searcher.Started.WaitAsync(Guard));
        time.Advance(WindowsUpdateCache.SearchTimeout);
        Assert.False(await first.WaitAsync(Guard));
        Assert.Null(cache.TryGet());

        Assert.False(await cache.RefreshAsync(CancellationToken.None).WaitAsync(Guard));
        Assert.False(await cache.RefreshAsync(CancellationToken.None).WaitAsync(Guard));
        Assert.Equal(1, searcher.Calls);
        Assert.Single(log.Warnings);

        // The blocked search ends; the next refresh starts a new one and stores its result.
        block.SetResult(Scan(3));
        var refreshed = false;
        for (var i = 0; i < 1000 && !refreshed; i++)
        {
            refreshed = await cache.RefreshAsync(CancellationToken.None).WaitAsync(Guard);
            if (!refreshed)
                await Task.Delay(10);
        }

        Assert.True(refreshed);
        Assert.Equal(2, searcher.Calls);
        Assert.Equal(3, cache.TryGet()!.Scan.PendingCount);
    }

    [Fact]
    public async Task UpdateCache_StartBeginsFirstSearchAndLoopRetrySkipsWhileItHangs()
    {
        var time = new ManualTimeProvider(T0);
        var block = new TaskCompletionSource<WindowsUpdateScan>();
        var searcher = new FakeUpdateSearcher(_ => block.Task);
        var log = new RecordingLogger();
        using var cache = new WindowsUpdateCache(searcher, time);
        Assert.Equal(0, searcher.Calls);

        cache.Start(log);
        Assert.True(await searcher.Started.WaitAsync(Guard));
        await WaitUntil(() => time.ActiveDueTimes().Contains(T0 + WindowsUpdateCache.SearchTimeout));
        time.Advance(WindowsUpdateCache.SearchTimeout);
        var retryAt = T0 + WindowsUpdateCache.SearchTimeout + WindowsUpdateCache.RetryAfterFailure;
        await WaitUntil(() => time.ActiveDueTimes().Contains(retryAt));

        time.Advance(WindowsUpdateCache.RetryAfterFailure);
        await WaitUntil(() => log.Warnings.Length == 1);
        Assert.Equal(1, searcher.Calls);
        block.SetResult(Scan(1));
    }

}
