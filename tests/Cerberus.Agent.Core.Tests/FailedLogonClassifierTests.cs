using System.Text.Json;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support evidence: pure classifier, aggregation, report shape and cursor logic for security.failed_logons.</summary>
public sealed class FailedLogonClassifierTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static FailedLogonEvent Sec(int? type, string? ip, double sec = 0, string? process = null)
        => new(FailedLogonSource.Security4625, T0.AddSeconds(sec), ip, type, process);

    private static FailedLogonEvent Rdp140(string ip, double sec = 0) => new(FailedLogonSource.RdpCore140, T0.AddSeconds(sec), ip);

    private static FailedLogonEvent Ssh(string ip, double sec = 0) => new(FailedLogonSource.OpenSsh, T0.AddSeconds(sec), ip);

    private static FailedLogonEvent Sql(string? ip, double sec = 0) => new(FailedLogonSource.Sql18456, T0.AddSeconds(sec), ip);

    [Fact]
    public void LogonType10_IsRdp()
    {
        var t = FailedLogonClassifier.Tally(new[] { Sec(10, "203.0.113.5"), Sec(10, "203.0.113.5", 1) });
        Assert.Equal(2, t.Counts["rdp"]);
        var g = Assert.Single(t.Groups);
        Assert.Equal(("rdp", "203.0.113.5", 2), (g.Protocol, g.SourceIp, g.Count));
    }

    [Fact]
    public void LogonType3_WithRdpCore140_IsRdpAndCountedOnce()
    {
        var t = FailedLogonClassifier.Tally(new[] { Sec(3, "198.51.100.7", 0), Rdp140("198.51.100.7", 2) });
        Assert.Equal(1, t.Counts["rdp"]);
        Assert.Equal(0, t.Counts["other"]);
        Assert.Equal(1, Assert.Single(t.Groups).Count);
    }

    [Fact]
    public void LogonType3_WithoutRdpCore140_IsOther_AndUnmatched140CountsAlone()
    {
        var t = FailedLogonClassifier.Tally(new[] { Sec(3, "198.51.100.7"), Rdp140("203.0.113.9", 1), Rdp140("198.51.100.7", 60) });
        Assert.Equal(1, t.Counts["other"]);
        Assert.Equal(2, t.Counts["rdp"]);
    }

    [Fact]
    public void Type3_WithoutAddress_ConsumesOnly140_ForNla()
    {
        var t = FailedLogonClassifier.Tally(new[] { Sec(3, "-"), Rdp140("192.0.2.4", 1) });
        Assert.Equal(1, t.Counts["rdp"]);
        Assert.Equal("192.0.2.4", Assert.Single(t.Groups).SourceIp);
    }

    [Fact]
    public void Sshd4625_ConsumesMatchingSshLogLine()
    {
        var t = FailedLogonClassifier.Tally(new[] { Sec(8, "-", 0, @"C:\Windows\System32\OpenSSH\sshd.exe"), Ssh("192.0.2.10", 1), Ssh("192.0.2.11", 120) });
        Assert.Equal(2, t.Counts["ssh"]);
        Assert.Equal(0, t.Counts["other"]);
    }

    [Theory]
    [InlineData("Failed password for root from 192.0.2.1 port 50022 ssh2", "192.0.2.1")]
    [InlineData("sshd: Failed password for invalid user admin from 192.0.2.2 port 4000 ssh2", "192.0.2.2")]
    [InlineData("Failed publickey for bob from 2001:db8::5 port 22 ssh2", "2001:db8::5")]
    [InlineData("Invalid user admin from 192.0.2.3 port 4001", null)]
    [InlineData("Accepted password for bob from 192.0.2.3 port 4001 ssh2", null)]
    public void SshMessage_Parsing(string text, string? expected)
        => Assert.Equal(expected, FailedLogonClassifier.ParseSshFailedIp(text));

    [Fact]
    public void SshMessage_AttackerControlledUserName_CannotSpoofAddress()
        => Assert.Equal("192.0.2.9", FailedLogonClassifier.ParseSshFailedIp("Failed password for x from 198.51.100.1 port 1 y from 192.0.2.9 port 22 ssh2"));

    [Fact]
    public void Sql18456_ClientAddress_IsSql()
    {
        Assert.Equal("203.0.113.20", FailedLogonClassifier.ParseSqlClientIp("Login failed. Reason: Password did not match. [CLIENT: 203.0.113.20]"));
        Assert.Null(FailedLogonClassifier.NormalizeIp(FailedLogonClassifier.ParseSqlClientIp("[CLIENT: <local machine>]")));
        var t = FailedLogonClassifier.Tally(new[] { Sql("203.0.113.20"), Sql("203.0.113.20", 5), Sql(null, 6) });
        Assert.Equal(3, t.Counts["sql"]);
        var g = Assert.Single(t.Groups);
        Assert.Equal(2, g.Count);
    }

    [Fact]
    public void Other_AndUnusableAddresses_CountButAreNotGrouped()
    {
        var t = FailedLogonClassifier.Tally(new[]
        {
            Sec(2, "192.0.2.50"), Sec(3, "-"), Sec(3, "::1"), Sec(3, "127.0.0.1"), Sec(3, "::ffff:192.0.2.51"), Sec(3, "garbage"),
        });
        Assert.Equal(6, t.Counts["other"]);
        Assert.Equal(new[] { "192.0.2.50", "192.0.2.51" }, t.Groups.Select(g => g.SourceIp).OrderBy(x => x));
    }

    [Fact]
    public void Top20_Truncation_AndOrdering()
    {
        var events = new List<FailedLogonEvent>();
        for (var i = 1; i <= 25; i++)
            for (var n = 0; n < i; n++)
                events.Add(Sec(10, $"203.0.113.{i}", n));
        var t = FailedLogonClassifier.Tally(events);
        var json = JsonDocument.Parse(JsonSerializer.Serialize(
            FailedLogonSection.Build("ok", T0, T0.AddMinutes(1), false, t, default, default, default))).RootElement;
        var groups = json.GetProperty("reported_groups");
        Assert.Equal(20, groups.GetArrayLength());
        Assert.True(json.GetProperty("truncated").GetBoolean());
        Assert.Equal(20, json.GetProperty("cap").GetInt32());
        Assert.Equal("203.0.113.25", groups[0].GetProperty("source_ip").GetString());
        Assert.Equal(325, json.GetProperty("protocols").GetProperty("rdp").GetProperty("failed_count").GetInt32());
    }

    [Fact]
    public void Report_Shape_HasNoUserNameField()
    {
        var t = FailedLogonClassifier.Tally(new[] { Sec(10, "203.0.113.5"), Ssh("192.0.2.1"), Sql("198.51.100.2") });
        var text = JsonSerializer.Serialize(FailedLogonSection.Build(
            "ok", T0, T0.AddMinutes(5), true, t, new ProtocolPresence(true, true), default, default));
        Assert.DoesNotContain("user", text, StringComparison.OrdinalIgnoreCase);
        var root = JsonDocument.Parse(text).RootElement;
        Assert.Equal("2026-03-01T12:00:00Z", root.GetProperty("window_start_utc").GetString());
        Assert.Equal("2026-03-01T12:05:00Z", root.GetProperty("window_end_utc").GetString());
        Assert.True(root.GetProperty("cursor_reset").GetBoolean());
        Assert.True(root.GetProperty("protocols").GetProperty("rdp").GetProperty("listening").GetBoolean());
        Assert.False(root.GetProperty("protocols").GetProperty("other").TryGetProperty("present", out _));
    }

    [Fact]
    public void ClassifiedEventRecord_CarriesNoAccountField()
        => Assert.DoesNotContain(typeof(FailedLogonEvent).GetProperties(), p => p.Name.Contains("User", StringComparison.OrdinalIgnoreCase));

    // saved, oldest, newest, stateInvalid, expected
    [Theory]
    [InlineData(null, 1L, 500L, false, (int)ChannelStart.FirstRun)]
    [InlineData(100L, 1L, 500L, false, (int)ChannelStart.Resume)]
    [InlineData(500L, 1L, 500L, false, (int)ChannelStart.Resume)]
    [InlineData(900L, 1L, 500L, false, (int)ChannelStart.Reset)]
    [InlineData(100L, 1L, 500L, true, (int)ChannelStart.Reset)]
    [InlineData(null, 0L, 0L, true, (int)ChannelStart.Reset)]
    [InlineData(100L, 300L, 500L, false, (int)ChannelStart.Gap)]
    [InlineData(299L, 300L, 500L, false, (int)ChannelStart.Resume)]
    [InlineData(298L, 300L, 500L, false, (int)ChannelStart.Gap)]
    [InlineData(0L, 0L, 0L, false, (int)ChannelStart.Resume)]
    public void CursorDecision(long? saved, long oldest, long newest, bool invalid, int expectedValue)
    {
        var decision = FailedLogonCursorLogic.Decide(saved, oldest, newest, invalid);
        Assert.Equal((ChannelStart)expectedValue, decision);
        var after = FailedLogonCursorLogic.StartAfter(decision, saved, oldest, newest);
        Assert.Equal(decision switch { ChannelStart.Resume => saved, ChannelStart.Gap => oldest - 1, _ => newest }, after);
        Assert.Equal(decision is ChannelStart.Reset or ChannelStart.Gap, FailedLogonCursorLogic.IsReset(decision));
    }

    [Fact]
    public void LogClearedEvent_IsNotCounted()
    {
        var t = FailedLogonClassifier.Tally(new[] { new FailedLogonEvent(FailedLogonSource.LogCleared, T0, null), Sec(10, "203.0.113.5") });
        Assert.Equal(1, t.Counts.Values.Sum());
    }

    private static string Seed(string dir, out FailedLogonCursorStore store)
    {
        var path = Path.Combine(dir, "c.json");
        store = new FailedLogonCursorStore(path);
        Assert.True(store.Save(new FailedLogonCursorState { LastWindowEndUtc = T0 }));
        return path;
    }

    private static string Start(object report) => JsonDocument.Parse(JsonSerializer.Serialize(report)).RootElement.GetProperty("window_start_utc").GetString()!;

    [Fact]
    public void Peek_DoesNotMoveCursor()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-peek-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Seed(dir, out var store);
            var before = File.ReadAllText(path);
            var report = FailedLogonSection.Collect(store, T0.AddMinutes(5), commit: false, CancellationToken.None);
            FailedLogonSection.CommitPending();
            Assert.Equal(before, File.ReadAllText(path));
            Assert.Equal("2026-03-01T12:00:00Z", Start(report));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Commit_OnlyAfterUpload_AndFailedUploadKeepsWindowStart()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-commit-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Seed(dir, out var store);
            var before = File.ReadAllText(path);

            // Collection 1: upload fails (no CommitPending) -> persisted cursor unchanged.
            Assert.Equal("2026-03-01T12:00:00Z", Start(FailedLogonSection.Collect(store, T0.AddMinutes(5), commit: true, CancellationToken.None)));
            Assert.Equal(before, File.ReadAllText(path));

            // Collection 2 starts at the last committed point; its upload succeeds -> cursor moves to its window end.
            Assert.Equal("2026-03-01T12:00:00Z", Start(FailedLogonSection.Collect(store, T0.AddMinutes(10), commit: true, CancellationToken.None)));
            FailedLogonSection.CommitPending();
            Assert.Equal(T0.AddMinutes(10), store.Load(out _).LastWindowEndUtc);

            // Collection 3 starts at the new committed point; a repeated commit is a no-op.
            Assert.Equal("2026-03-01T12:10:00Z", Start(FailedLogonSection.Collect(store, T0.AddMinutes(15), commit: false, CancellationToken.None)));
            FailedLogonSection.CommitPending();
            Assert.Equal(T0.AddMinutes(10), store.Load(out _).LastWindowEndUtc);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void CursorStore_RoundTrip_MissingAndInvalidFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-cursor-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Path.Combine(dir, "c.json");
            var store = new FailedLogonCursorStore(path);
            var fresh = store.Load(out var invalid);
            Assert.False(invalid);
            Assert.Empty(fresh.Channels);

            fresh.Channels["Security"] = 42;
            fresh.LastWindowEndUtc = T0;
            Assert.True(store.Save(fresh));
            var loaded = store.Load(out invalid);
            Assert.False(invalid);
            Assert.Equal(42, loaded.Channels["security"]);
            Assert.Equal(T0, loaded.LastWindowEndUtc);

            File.WriteAllText(path, "{ not json");
            store.Load(out invalid);
            Assert.True(invalid);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }
}
