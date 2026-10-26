using System.Text.Json.Nodes;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Reader whose calls are counted and scripted by call number; no WMI.</summary>
internal sealed class FakePostureReader : ISecurityPostureReader
{
    private int _defender;
    private int _smb1;

    public Func<int, object> Defender { get; set; } = n => new { status = "ok", n };

    public Func<int, object> Smb1 { get; set; } = n => new { status = "ok", n };

    public int DefenderCalls => Volatile.Read(ref _defender);

    public int Smb1Calls => Volatile.Read(ref _smb1);

    public object ReadDefender(CancellationToken ct) => Defender(Interlocked.Increment(ref _defender));

    public object ReadSmb1(CancellationToken ct) => Smb1(Interlocked.Increment(ref _smb1));
}

/// <summary>Unit evidence: the background posture cache (single flight, refresh, retry, TTL) and the security collector's use of it.</summary>
[Collection("FailedLogonCursor")]
public sealed class SecurityPostureCacheTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static void WaitFor(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
                Assert.Fail("timed out waiting for " + what);
            Thread.Sleep(5);
        }
    }

    private static string DefenderStatus(SecurityPostureCache cache) => (string)Obj(cache.Current()["defender_av"]!)["status"]!;

    private static int DefenderN(SecurityPostureCache cache) => Obj(cache.Current()["defender_av"]!)["n"] is JsonValue v ? (int)v : -1;

    // The failure path records its retry time on a background thread after the reader threw; give it a moment.
    private static void SettleAfterFailure() => Thread.Sleep(150);

    [Fact]
    public void HungReader_RepeatedCurrentNeverStartsASecondQuery_AndStaysUnavailable()
    {
        using var gate = new ManualResetEventSlim(false);
        var reader = new FakePostureReader { Defender = n => Hang(gate, n), Smb1 = n => Hang(gate, n) };
        var time = new ManualTimeProvider(T0);
        using var cache = new SecurityPostureCache(reader, time);
        try
        {
            for (var i = 0; i < 20; i++)
            {
                Assert.Equal("unavailable", DefenderStatus(cache));
                time.Advance(TimeSpan.FromMinutes(3));
            }

            // Each key starts its own background query; wait for both before counting.
            WaitFor(() => reader.DefenderCalls >= 1 && reader.Smb1Calls >= 1, "first defender and smb1 queries");
            Assert.Equal("unavailable", DefenderStatus(cache));
            Thread.Sleep(100); // a wrongly started second query would begin within this window
            Assert.Equal(1, reader.DefenderCalls);
            Assert.Equal(1, reader.Smb1Calls);
        }
        finally
        {
            gate.Set();
        }
    }

    [Fact]
    public void FirstCurrentOrWarm_StartsEachReaderOnce()
    {
        var viaCurrent = new FakePostureReader();
        using (var cache = new SecurityPostureCache(viaCurrent, new ManualTimeProvider(T0)))
        {
            Assert.Equal("unavailable", DefenderStatus(cache));
            WaitFor(() => viaCurrent.DefenderCalls == 1 && viaCurrent.Smb1Calls == 1, "first queries");
            WaitFor(() => DefenderStatus(cache) == "ok", "first value");
            Assert.Equal(1, viaCurrent.DefenderCalls);
            Assert.Equal(1, viaCurrent.Smb1Calls);
            Assert.Equal(new[] { "defender_av", "smb1" }, cache.Current().Keys.OrderBy(k => k, StringComparer.Ordinal));
        }

        var viaWarm = new FakePostureReader();
        using (var cache = new SecurityPostureCache(viaWarm, new ManualTimeProvider(T0)))
        {
            cache.Warm();
            cache.Warm();
            WaitFor(() => viaWarm.DefenderCalls == 1 && viaWarm.Smb1Calls == 1, "warm queries");
            WaitFor(() => DefenderStatus(cache) == "ok", "warm value");
            Assert.Equal(1, viaWarm.DefenderCalls);
        }
    }

    [Fact]
    public void Refresh_StartsOnlyAfterFifteenMinutes_AndTheNewValueReplacesTheOld()
    {
        var reader = new FakePostureReader();
        var time = new ManualTimeProvider(T0);
        using var cache = new SecurityPostureCache(reader, time);
        cache.Warm();
        WaitFor(() => DefenderStatus(cache) == "ok", "first value");
        Assert.Equal(1, DefenderN(cache));

        time.Advance(TimeSpan.FromMinutes(14).Add(TimeSpan.FromSeconds(59)));
        Assert.Equal(1, DefenderN(cache));

        time.Advance(TimeSpan.FromSeconds(1));
        cache.Warm();
        WaitFor(() => DefenderN(cache) == 2, "refreshed value");
        Assert.Equal(2, reader.DefenderCalls);
    }

    [Fact]
    public void FailedRefresh_KeepsTheLastGoodValue_AndRetriesAfterFiveMinutes()
    {
        var reader = new FakePostureReader();
        reader.Defender = n => n == 2 ? throw new InvalidOperationException("wmi down") : new { status = "ok", n };
        var time = new ManualTimeProvider(T0);
        using var cache = new SecurityPostureCache(reader, time);
        cache.Warm();
        WaitFor(() => DefenderN(cache) == 1, "first value");

        time.Advance(SecurityPostureCache.RefreshAfter);
        cache.Warm();
        WaitFor(() => reader.DefenderCalls == 2, "failing refresh");
        SettleAfterFailure();
        Assert.Equal(1, DefenderN(cache)); // last good value survives

        time.Advance(TimeSpan.FromMinutes(4).Add(TimeSpan.FromSeconds(59)));
        Assert.Equal(1, DefenderN(cache));
        Assert.Equal(2, reader.DefenderCalls); // retry not due yet

        time.Advance(TimeSpan.FromSeconds(1));
        cache.Warm();
        WaitFor(() => DefenderN(cache) == 3, "retry value");
        Assert.Equal(3, reader.DefenderCalls);
    }

    [Fact]
    public void FirstReadFailing_StaysUnavailable_AndRetriesAfterFiveMinutes()
    {
        var reader = new FakePostureReader();
        reader.Defender = n => n == 1 ? throw new InvalidOperationException("wmi down") : new { status = "ok", n };
        var time = new ManualTimeProvider(T0);
        using var cache = new SecurityPostureCache(reader, time);
        cache.Warm();
        WaitFor(() => reader.DefenderCalls == 1, "failing query");
        SettleAfterFailure();

        time.Advance(TimeSpan.FromMinutes(4).Add(TimeSpan.FromSeconds(59)));
        Assert.Equal("unavailable", DefenderStatus(cache));
        Assert.Equal(1, reader.DefenderCalls);

        time.Advance(TimeSpan.FromSeconds(1));
        cache.Warm();
        WaitFor(() => DefenderStatus(cache) == "ok", "retried value");
        Assert.Equal(2, reader.DefenderCalls);
    }

    [Fact]
    public void ValueOlderThanTwoHours_IsUnavailable()
    {
        using var gate = new ManualResetEventSlim(false);
        var reader = new FakePostureReader { Defender = n => n == 1 ? new { status = "ok", n } : Hang(gate, n) };
        var time = new ManualTimeProvider(T0);
        using var cache = new SecurityPostureCache(reader, time);
        try
        {
            cache.Warm();
            WaitFor(() => DefenderStatus(cache) == "ok", "first value");

            time.Advance(SecurityPostureCache.Ttl);
            Assert.Equal("ok", DefenderStatus(cache)); // exactly at the TTL it still counts (second query now hangs)

            time.Advance(TimeSpan.FromSeconds(1));
            Assert.Equal("unavailable", DefenderStatus(cache));
        }
        finally
        {
            gate.Set();
        }
    }

    private static object Hang(ManualResetEventSlim gate, int n)
    {
        gate.Wait(TimeSpan.FromSeconds(30));
        return new { status = "ok", n };
    }

    // ---- collector use of the cache ----------------------------------------------------------------------------

    private static SecurityTelemetrySectionCollector Collector(bool server, SecurityPostureCache cache, string dir)
        => new(commitFailedLogons: false, server, new FailedLogonCursorStore(Path.Combine(dir, "c.json")), cache);

    private static string TempDir() => Path.Combine(Path.GetTempPath(), "fl-posture-" + Guid.NewGuid().ToString("N"));

    private static void Cleanup(string dir)
    {
        if (Directory.Exists(dir))
            Directory.Delete(dir, true);
    }

    [Fact]
    public async Task ServerProfileCollector_WarmsTheReaderExactlyOnce_DesktopProfileNever()
    {
        var dir = TempDir();
        try
        {
            var desktopReader = new FakePostureReader();
            using var desktopCache = new SecurityPostureCache(desktopReader, new ManualTimeProvider(T0));
            var desktop = Obj(await Collector(false, desktopCache, dir).CollectAsync(Context(), CancellationToken.None));
            Thread.Sleep(100);
            Assert.Equal(0, desktopReader.DefenderCalls);
            Assert.Equal(0, desktopReader.Smb1Calls);
            Assert.False(desktop.ContainsKey("defender_av"));

            var serverReader = new FakePostureReader();
            using var serverCache = new SecurityPostureCache(serverReader, new ManualTimeProvider(T0));
            var collector = Collector(true, serverCache, dir);
            WaitFor(() => serverReader.DefenderCalls == 1 && serverReader.Smb1Calls == 1, "warm on construction");

            await collector.CollectAsync(Context(), CancellationToken.None);
            await collector.CollectAsync(Context(), CancellationToken.None);
            Assert.Equal(1, serverReader.DefenderCalls);
            Assert.Equal(1, serverReader.Smb1Calls);
        }
        finally
        {
            Cleanup(dir);
        }
    }

    [Fact]
    public async Task ServerCollector_WithHungReader_ReturnsPromptlyWithUnavailablePostureAndFailedLogons()
    {
        var dir = TempDir();
        using var gate = new ManualResetEventSlim(false);
        try
        {
            var reader = new FakePostureReader { Defender = n => Hang(gate, n), Smb1 = n => Hang(gate, n) };
            using var cache = new SecurityPostureCache(reader, new ManualTimeProvider(T0));
            var collector = Collector(true, cache, dir);

            var node = Obj(await collector.CollectAsync(Context(), CancellationToken.None).AsTask().WaitAsync(TimeSpan.FromSeconds(60)));

            Assert.Equal("unavailable", (string)node["defender_av"]!["status"]!);
            Assert.Equal("unavailable", (string)node["smb1"]!["status"]!);
            Assert.True(node.ContainsKey("failed_logons"));
        }
        finally
        {
            gate.Set();
            Cleanup(dir);
        }
    }

    [Fact]
    public async Task ServerCollector_WithThrowingReader_ReportsUnavailablePostureAndKeepsFailedLogons()
    {
        var dir = TempDir();
        try
        {
            var reader = new FakePostureReader
            {
                Defender = _ => throw new InvalidOperationException("boom"),
                Smb1 = _ => throw new InvalidOperationException("boom"),
            };
            using var cache = new SecurityPostureCache(reader, new ManualTimeProvider(T0));
            var collector = Collector(true, cache, dir);
            WaitFor(() => reader.DefenderCalls == 1 && reader.Smb1Calls == 1, "failing queries");

            var node = Obj(await collector.CollectAsync(Context(), CancellationToken.None).AsTask().WaitAsync(TimeSpan.FromSeconds(60)));

            Assert.Equal("unavailable", (string)node["defender_av"]!["status"]!);
            Assert.Equal("unavailable", (string)node["smb1"]!["status"]!);
            Assert.True(node.ContainsKey("failed_logons"));
        }
        finally
        {
            Cleanup(dir);
        }
    }
}
