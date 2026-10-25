using System.ServiceProcess;
using System.Text;
using System.Text.Json.Nodes;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Server fact sections: Windows Update cache, shared time budget, catalog and snapshot caps.</summary>
public sealed partial class ServerFactSectionsTests
{
    // ---- Windows Update cache --------------------------------------------------------------------------------

    private static readonly TimeSpan Guard = TimeSpan.FromSeconds(10);

    private static WindowsUpdateScan Scan(int pending) => new(pending, 0, Array.Empty<WindowsUpdateEntry>());

    [Fact]
    public async Task UpdateCache_StoresResultAndExpiresAfterTwoHours()
    {
        var time = new ManualTimeProvider(T0);
        using var cache = new WindowsUpdateCache(new FakeUpdateSearcher(_ => Task.FromResult(Scan(4))), time);
        Assert.Null(cache.TryGet());

        Assert.True(await cache.RefreshAsync(CancellationToken.None));
        Assert.Equal(4, cache.TryGet()!.Scan.PendingCount);
        Assert.Equal(T0, cache.TryGet()!.CheckedAt);

        time.Advance(TimeSpan.FromHours(2));
        Assert.NotNull(cache.TryGet());
        time.Advance(TimeSpan.FromSeconds(1));
        Assert.Null(cache.TryGet());
    }

    [Fact]
    public async Task UpdateCache_SearchOverSixtySecondsTimesOutAndKeepsPreviousEntry()
    {
        var time = new ManualTimeProvider(T0);
        var block = new TaskCompletionSource<WindowsUpdateScan>();
        var first = true;
        var searcher = new FakeUpdateSearcher(_ =>
        {
            if (!first)
                return block.Task;
            first = false;
            return Task.FromResult(Scan(1));
        });
        using var cache = new WindowsUpdateCache(searcher, time);
        Assert.True(await cache.RefreshAsync(CancellationToken.None));

        time.Advance(TimeSpan.FromMinutes(51));
        var second = cache.RefreshAsync(CancellationToken.None);
        time.Advance(TimeSpan.FromSeconds(60));

        Assert.False(await second.WaitAsync(Guard));
        Assert.Equal(1, cache.TryGet()!.Scan.PendingCount);
        block.SetResult(Scan(7));
    }

    [Fact]
    public async Task UpdateCache_SearcherFailureIsReportedAsFalseWithoutThrowing()
    {
        using var cache = new WindowsUpdateCache(new FakeUpdateSearcher(_ => throw new InvalidOperationException("boom")), new ManualTimeProvider(T0));

        Assert.False(await cache.RefreshAsync(CancellationToken.None));
        Assert.Null(cache.TryGet());
    }

    [Fact]
    public async Task UpdateCache_BackgroundLoopSearchesAgainOnlyAfterFiftyMinutes()
    {
        var time = new ManualTimeProvider(T0);
        var searcher = new FakeUpdateSearcher(_ => Task.FromResult(Scan(2)));
        using var cache = new WindowsUpdateCache(searcher, time);
        Assert.Equal(0, searcher.Calls);

        cache.Start();
        Assert.True(await searcher.Started.WaitAsync(TimeSpan.FromSeconds(10)));
        await WaitUntil(() => time.ActiveDueTimes().Contains(T0 + WindowsUpdateCache.RefreshAfter));

        time.Advance(TimeSpan.FromMinutes(49));
        Assert.Equal(1, searcher.Calls);
        time.Advance(TimeSpan.FromMinutes(1));
        Assert.True(await searcher.Started.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(2, searcher.Calls);
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        for (var i = 0; i < 1000 && !condition(); i++)
            await Task.Delay(10);
        Assert.True(condition());
    }

    // ---- shared time budget ----------------------------------------------------------------------------------

    private static readonly object Ok = new { status = "ok" };

    [Fact]
    public async Task Budget_SectionBlockedPastFiveSecondsIsUnavailable()
    {
        var time = new ManualTimeProvider(T0);
        var blocked = new TaskCompletionSource<object>();
        var inner = new StubSection("services", _ => new ValueTask<object>(blocked.Task));
        var run = new ServerSectionBudget(inner, time).CollectAsync(Context(), CancellationToken.None);

        time.Advance(TimeSpan.FromSeconds(4.9));
        Assert.False(run.IsCompleted);
        time.Advance(TimeSpan.FromSeconds(0.1));

        var node = Obj(await run.AsTask().WaitAsync(Guard));
        Assert.Equal("unavailable", (string)node["status"]!);
        Assert.Equal("services", (string)node["section"]!);
        blocked.SetResult(Ok);
    }

    [Fact]
    public async Task Budget_FastSectionPassesThroughItsResult()
    {
        var inner = new StubSection("hardware", _ => new ValueTask<object>(Ok));
        var result = await new ServerSectionBudget(inner, new ManualTimeProvider(T0)).CollectAsync(Context(), CancellationToken.None);

        Assert.Same(Ok, result);
    }

    [Fact]
    public async Task Budget_TwentySecondsAreSharedAcrossSectionsOfOneRun()
    {
        var time = new ManualTimeProvider(T0);
        var context = Context();
        var first = new ServerSectionBudget(new StubSection("sessions", _ => new ValueTask<object>(Ok)), time);
        await first.CollectAsync(context, CancellationToken.None);

        time.Advance(TimeSpan.FromSeconds(18));
        var blocked = new TaskCompletionSource<object>();
        var second = new ServerSectionBudget(new StubSection("services", _ => new ValueTask<object>(blocked.Task)), time);
        var run = second.CollectAsync(context, CancellationToken.None);
        time.Advance(TimeSpan.FromSeconds(1.9));
        Assert.False(run.IsCompleted);
        time.Advance(TimeSpan.FromSeconds(0.1));
        Assert.Equal("unavailable", (string)Obj(await run.AsTask().WaitAsync(Guard))["status"]!);

        var late = new StubSection("software", _ => new ValueTask<object>(Ok));
        var lateNode = Obj(await new ServerSectionBudget(late, time).CollectAsync(context, CancellationToken.None));
        Assert.Equal("unavailable", (string)lateNode["status"]!);
        Assert.Equal(0, late.Calls);

        var fresh = new StubSection("software", _ => new ValueTask<object>(Ok));
        Assert.Same(Ok, await new ServerSectionBudget(fresh, time).CollectAsync(Context(), CancellationToken.None));
        blocked.SetResult(Ok);
    }

    [Fact]
    public async Task Budget_CallerCancellationIsNotReportedAsUnavailable()
    {
        var time = new ManualTimeProvider(T0);
        using var cts = new CancellationTokenSource();
        var inner = new StubSection("services", ct => new ValueTask<object>(new TaskCompletionSource<object>().Task));
        var run = new ServerSectionBudget(inner, time).CollectAsync(Context(), cts.Token);

        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await run.AsTask().WaitAsync(Guard));
    }

    // ---- catalog and profile caps ----------------------------------------------------------------------------

#if CERBERUS_SERVER_PROFILE
    [Fact]
    public void Catalog_ServerProfileCarriesAllFourteenSectionsWithCap262144()
    {
        var names = WindowsTelemetrySectionCatalog.CreateDefault((string?)null).Select(s => s.SectionName).ToArray();

        Assert.Equal(14, names.Length);
        Assert.Subset(names.ToHashSet(), SixSections.ToHashSet());
        Assert.Equal(262144, AgentTelemetryLimits.MaxSnapshotBytes);
        var wrapped = WindowsTelemetrySectionCatalog.CreateServerFactSections(new ManualTimeProvider(T0));
        Assert.Equal(SixSections.OrderBy(n => n), wrapped.Select(s => s.SectionName).OrderBy(n => n));
        Assert.All(wrapped, s => Assert.IsType<ServerSectionBudget>(s));
    }

    [Fact]
    public void Catalog_ServerProfileBudgetsCoreSectionsToo_SoTheRunClockStartsAtTheFirstSection()
    {
        var sections = WindowsTelemetrySectionCatalog.CreateDefault((string?)null);

        Assert.All(sections, s => Assert.IsType<ServerSectionBudget>(s));
        Assert.Contains(sections, s => s.SectionName == "security");
        Assert.Contains(sections, s => s.SectionName == "identity");
    }

    [Fact]
    public async Task Budget_SlowFirstCoreSectionStartsTheRunClockAndIsCutAtFiveSeconds()
    {
        var time = new ManualTimeProvider(T0);
        var context = Context();
        var blocked = new TaskCompletionSource<object>();
        var core = new ServerSectionBudget(new StubSection("security", _ => new ValueTask<object>(blocked.Task)), time);
        var run = core.CollectAsync(context, CancellationToken.None);

        time.Advance(TimeSpan.FromSeconds(5));
        Assert.Equal("unavailable", (string)Obj(await run.AsTask().WaitAsync(Guard))["status"]!);

        time.Advance(TimeSpan.FromSeconds(15));
        var late = new StubSection("software", _ => new ValueTask<object>(Ok));
        var lateNode = Obj(await new ServerSectionBudget(late, time).CollectAsync(context, CancellationToken.None));
        Assert.Equal("unavailable", (string)lateNode["status"]!);
        Assert.Equal(0, late.Calls);
        blocked.SetResult(Ok);
    }

    private static Dictionary<string, object?> BigSections()
        => new(StringComparer.Ordinal)
        {
            ["software"] = SoftwareTelemetrySectionCollector.Build(Enumerable.Range(0, 500).Select(i =>
                new SoftwareTelemetrySectionCollector.RawSoftware(Fill($"app{i:D4}", 128), Fill("v", 64), Fill("p", 128), "20240101", "x64"))),
            ["services"] = ServicesTelemetrySectionCollector.Build(Enumerable.Range(0, 400).Select(i =>
                new ServicesTelemetrySectionCollector.RawService(Fill($"svc{i:D4}", 64), Fill("d", 128), "running", "auto"))),
            ["listening_ports"] = ListeningPortsTelemetrySectionCollector.Build(Enumerable.Range(1, 256).Select(i =>
                new ListeningPortsTelemetrySectionCollector.RawPort("tcp", "ipv4", i, "any", Fill("p", 64)))),
        };

    [Fact]
    public void Snapshot_OverCapHalvesSoftwareFirstAndMarksTruncated()
    {
        var snapshot = AgentSnapshotFactory.Create(Metadata(), T0, BigSections());

        Assert.True(AgentTelemetryLimits.EstimateJsonBytes(snapshot) <= 262144);
        var software = Obj(snapshot.Sections["software"]!);
        Assert.True(software["software"]!.AsArray().Count is > 0 and < 500);
        Assert.True((bool)software["truncated"]!);
        Assert.Equal(400, Obj(snapshot.Sections["services"]!)["services"]!.AsArray().Count);
        Assert.False((bool)Obj(snapshot.Sections["services"]!)["truncated"]!);
        Assert.Equal(256, Obj(snapshot.Sections["listening_ports"]!)["ports"]!.AsArray().Count);
        Assert.Equal(AgentSnapshotFactory.HashSection(snapshot.Sections["software"]), snapshot.SectionHashes["software"]);
    }

    [Fact]
    public void Snapshot_StillOverCapAfterHalvingIsRejected()
    {
        var sections = BigSections();
        sections["identity"] = new { status = "ok", blob = new string('a', 300_000) };

        Assert.Throws<InvalidOperationException>(() => AgentSnapshotFactory.Create(Metadata(), T0, sections));
    }

    [Fact]
    public async Task OfflineBuffer_ServerSnapshotRecordMayExceed64KiBButOtherKindsMayNot()
    {
        var path = Path.Combine(Path.GetTempPath(), $"cerberus-offline-{Guid.NewGuid():N}.json");
        try
        {
            var buffer = new OfflineTelemetryBuffer(path);
            var body = new { blob = new string('a', 100 * 1024) };

            await buffer.EnqueueAsync(OfflineTelemetryKinds.Snapshot, body, "snap", priority: 1, CancellationToken.None);
            Assert.Single(await buffer.ReadBatchAsync(10, CancellationToken.None));
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                buffer.EnqueueAsync(OfflineTelemetryKinds.Events, body, "ev", priority: 1, CancellationToken.None));
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    [Fact]
    public async Task RealCollection_ServerSnapshotFromThisMachineFitsCapAndPassesFactory()
    {
        var sections = new IWindowsTelemetrySectionCollector[]
        {
            new SessionsTelemetrySectionCollector(), new HardwareTelemetrySectionCollector(), new ServicesTelemetrySectionCollector(),
            new ListeningPortsTelemetrySectionCollector(), EmptyCacheUpdates(), new SoftwareTelemetrySectionCollector(),
        };

        var snapshot = await new WindowsTelemetryCollector(sections).BuildSnapshotAsync(Metadata(), null, CancellationToken.None);

        Assert.Equal(SixSections.OrderBy(n => n), snapshot.Sections.Keys.OrderBy(n => n));
        Assert.True(AgentTelemetryLimits.EstimateJsonBytes(snapshot) <= 262144);
        Assert.All(snapshot.Sections.Values, v => Assert.Equal("ok", (string)Obj(v!)["status"]!));
    }
#else
    [Fact]
    public void Catalog_DesktopProfileStaysAtElevenSectionsAnd64KiB()
    {
        var names = WindowsTelemetrySectionCatalog.CreateDefault((string?)null).Select(s => s.SectionName).ToArray();

        Assert.Equal(11, names.Length);
        Assert.DoesNotContain(WindowsTelemetrySectionCatalog.CreateDefault((string?)null), s => s is ServerSectionBudget);
        Assert.Empty(names.Intersect(SixSections));
        Assert.Equal(AgentTelemetryLimits.MaxJsonBytes, AgentTelemetryLimits.MaxSnapshotBytes);
        Assert.Equal(64 * 1024, AgentTelemetryLimits.MaxSnapshotBytes);
    }

    [Fact]
    public void Snapshot_DesktopRejectsServerSectionsAndKeepsThe64KiBCap()
    {
        foreach (var section in SixSections)
            Assert.Throws<InvalidOperationException>(() => AgentSnapshotFactory.Create(
                Metadata(), T0, new Dictionary<string, object?> { [section] = new { status = "ok" } }));

        Assert.Throws<InvalidOperationException>(() => AgentSnapshotFactory.Create(
            Metadata(), T0, new Dictionary<string, object?> { ["identity"] = new { blob = new string('a', 70_000) } }));
    }

    [Fact]
    public async Task OfflineBuffer_DesktopSnapshotRecordStaysCappedAt64KiB()
    {
        var path = Path.Combine(Path.GetTempPath(), $"cerberus-offline-{Guid.NewGuid():N}.json");
        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => new OfflineTelemetryBuffer(path)
                .EnqueueAsync(OfflineTelemetryKinds.Snapshot, new { blob = new string('a', 100 * 1024) }, "snap", priority: 1, CancellationToken.None));
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }
#endif
}
