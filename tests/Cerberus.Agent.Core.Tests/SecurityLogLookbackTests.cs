using System.Text.Json;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Support evidence for the successful-logon look-back: query bounds, the bounded reader loop and the cursor flag that
/// ends it. No event log is read except in the CollectAll test, which accepts the Security log being unreadable.
/// </summary>
[Collection("FailedLogonCursor")]
public sealed class SecurityLogLookbackTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static FailedLogonEventReader.ScannedRecord Logon(long id, string user)
        => new(id, SecurityLogEventParser.Logon(T0.AddMinutes(-id), new Dictionary<string, string>
        {
            ["LogonType"] = "10",
            ["TargetUserName"] = user,
        }));

    private static FailedLogonEventReader.ScannedRecord Failed(long id)
        => new(id, new FailedLogonEvent(FailedLogonSource.Security4625, T0, "203.0.113.9", 10));

    private static string[] Users(IEnumerable<FailedLogonEvent> events)
        => events.Select(e => ((SuccessfulLogon)e.Detail!).User!).ToArray();

    [Fact]
    public void Query_BoundsRecordIdWeekAndInteractiveTypes()
    {
        var query = FailedLogonEventReader.RecentLogonsQuery(42, FailedLogonEventReader.LogonLookback);

        Assert.Contains("(EventID=4624)", query);
        Assert.Contains("(EventRecordID <= 42)", query);
        Assert.Contains("timediff(@SystemTime) <= 604800000", query);
        Assert.Contains("Data[@Name='LogonType']=10 or Data[@Name='LogonType']=2", query);
        Assert.DoesNotContain("4625", query);
    }

    [Fact]
    public void TakeNewest_KeepsOnlySuccessfulLogonsInInputOrderUpToMax()
    {
        var records = new[] { Logon(1, "a"), new(2, null), Failed(3), Logon(4, "b"), Logon(5, "c") };

        var taken = FailedLogonEventReader.TakeNewest(records, maxEvents: 2, maxScanned: 100, CancellationToken.None, CancellationToken.None);

        Assert.Equal(new[] { "a", "b" }, Users(taken));
    }

    [Fact]
    public void TakeNewest_StopsAtTheScanCap()
    {
        var records = new[] { new(1, null), Logon(2, "a"), Logon(3, "b") };

        var taken = FailedLogonEventReader.TakeNewest(records, maxEvents: 10, maxScanned: 2, CancellationToken.None, CancellationToken.None);

        Assert.Equal(new[] { "a" }, Users(taken));
    }

    [Fact]
    public void TakeNewest_ReadCancelledByTheBudgetKeepsWhatWasFound()
    {
        using var budget = new CancellationTokenSource();

        IEnumerable<FailedLogonEventReader.ScannedRecord> Records()
        {
            yield return Logon(1, "a");
            budget.Cancel();
            throw new OperationCanceledException();
        }

        var taken = FailedLogonEventReader.TakeNewest(Records(), maxEvents: 10, maxScanned: 100, budget.Token, CancellationToken.None);

        Assert.Equal(new[] { "a" }, Users(taken));
    }

    [Fact]
    public void TakeNewest_CancellationOutsideTheBudgetPropagates()
    {
        using var caller = new CancellationTokenSource();
        caller.Cancel();
        static IEnumerable<FailedLogonEventReader.ScannedRecord> Throwing()
        {
            yield return Logon(1, "a");
            throw new OperationCanceledException();
        }

        Assert.Throws<OperationCanceledException>(
            () => FailedLogonEventReader.TakeNewest(new[] { Logon(1, "a") }, 10, 100, caller.Token, caller.Token));
        Assert.Throws<OperationCanceledException>(
            () => FailedLogonEventReader.TakeNewest(Throwing(), 10, 100, CancellationToken.None, CancellationToken.None));
    }

    [Fact]
    public void Cursor_OlderFileIsNotSeeded_AndTheFlagRoundTripsAtVersion1()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-seed-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Path.Combine(dir, "c.json");
            var store = new FailedLogonCursorStore(path);
            Assert.True(store.Save(new FailedLogonCursorState()));
            File.WriteAllText(path, "{\"version\":1,\"last_window_end_utc\":\"2026-03-01T12:00:00+00:00\",\"log_cleared_seeded\":true,\"channels\":{\"Security\":5}}");

            var old = store.Load(out var invalid);

            Assert.False(invalid);
            Assert.False(old.SuccessfulLogonsSeeded);
            old.SuccessfulLogonsSeeded = true;
            Assert.True(store.Save(old));
            using var json = JsonDocument.Parse(File.ReadAllText(path));
            Assert.Equal(1, json.RootElement.GetProperty("version").GetInt32());
            Assert.True(json.RootElement.GetProperty("successful_logons_seeded").GetBoolean());
            Assert.True(store.Load(out invalid).SuccessfulLogonsSeeded);
            Assert.False(invalid);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void CollectAll_PeekNeverSeeds_CommitSeedsOnlyWhenTheSecurityLogWasRead()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-seedrun-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FailedLogonCursorStore(Path.Combine(dir, "c.json"));
            Assert.True(store.Save(new FailedLogonCursorState { LastWindowEndUtc = T0 }));

            FailedLogonSection.CollectAll(store, T0.AddMinutes(5), commit: false, CancellationToken.None);
            FailedLogonSection.CommitPending();
            Assert.False(store.Load(out _).SuccessfulLogonsSeeded);

            var commit = FailedLogonSection.CollectAll(store, T0.AddMinutes(10), commit: true, CancellationToken.None);
            FailedLogonSection.KeepPendingIfReported(new Dictionary<string, object?> { ["failed_logons"] = commit.FailedLogons });
            FailedLogonSection.CommitPending();

            var read = (string)Obj(commit.SuccessfulLogons)["status"]! != "unavailable";
            Assert.Equal(read, store.Load(out _).SuccessfulLogonsSeeded);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void CollectAll_FirstRunSavesTheBaselineUnseeded()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-seedfirst-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new FailedLogonCursorStore(Path.Combine(dir, "c.json"));

            FailedLogonSection.CollectAll(store, T0, commit: true, CancellationToken.None);
            FailedLogonSection.CommitPending();

            Assert.False(store.Load(out _).SuccessfulLogonsSeeded);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }
}
