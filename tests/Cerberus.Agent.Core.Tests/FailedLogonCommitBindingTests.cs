using System.Text.Json;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Support evidence: the failed-logon cursor moves only for a window whose report object is in the snapshot that was
/// uploaded; read-position and SQL provider rules of the failed-logon reader.
/// </summary>
[Collection("FailedLogonCursor")]
public sealed class FailedLogonCommitBindingTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private sealed class StubSection(string name, Func<object> collect) : IWindowsTelemetrySectionCollector
    {
        public string SectionName => name;

        public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct) => ValueTask.FromResult(collect());
    }

    private static AgentBuildMetadata Metadata() => new("1.2.3", "build-1", "dev", "boot-1", AgentSchemaVersions.All);

    private static FailedLogonCursorStore Seed(out string dir)
    {
        dir = Path.Combine(Path.GetTempPath(), "fl-bind-" + Guid.NewGuid().ToString("N"));
        var store = new FailedLogonCursorStore(Path.Combine(dir, "c.json"));
        Assert.True(store.Save(new FailedLogonCursorState { LastWindowEndUtc = T0 }));
        return store;
    }

    private static async Task Upload(params IWindowsTelemetrySectionCollector[] sections)
    {
        var collector = new WindowsTelemetryCollector(sections);
        await collector.BuildSnapshotAsync(Metadata(), null, CancellationToken.None);
        collector.MarkSnapshotSubmitted();
    }

    [Fact]
    public async Task ReportedWindow_CommitsAfterUpload()
    {
        var store = Seed(out var dir);
        try
        {
            await Upload(new StubSection("security", () => new Dictionary<string, object?>
            {
                ["failed_logons"] = FailedLogonSection.Collect(store, T0.AddMinutes(5), commit: true, CancellationToken.None),
            }));
            Assert.Equal(T0.AddMinutes(5), store.Load(out _).LastWindowEndUtc);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task FailedOrCancelledCollect_DoesNotCommitEarlierPendingWindow()
    {
        var store = Seed(out var dir);
        try
        {
            FailedLogonSection.Collect(store, T0.AddMinutes(5), commit: true, CancellationToken.None);
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            Assert.ThrowsAny<OperationCanceledException>(
                () => FailedLogonSection.Collect(store, T0.AddMinutes(10), commit: true, cts.Token));
            FailedLogonSection.CommitPending();
            Assert.Equal(T0, store.Load(out _).LastWindowEndUtc);

            // Same outcome through the snapshot path: the section throws, the capture reports it as failed.
            FailedLogonSection.Collect(store, T0.AddMinutes(5), commit: true, CancellationToken.None);
            await Upload(new StubSection("security", () => throw new InvalidOperationException("collect failed")));
            Assert.Equal(T0, store.Load(out _).LastWindowEndUtc);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task SectionWithoutThisReport_DoesNotCommit()
    {
        var store = Seed(out var dir);
        try
        {
            // Budget exhausted / timed out: the snapshot carries the unavailable stand-in, not the collected report.
            await Upload(new StubSection("security", () =>
            {
                FailedLogonSection.Collect(store, T0.AddMinutes(5), commit: true, CancellationToken.None);
                return ServerFactText.Unavailable("security", "time_budget_exhausted");
            }));
            Assert.Equal(T0, store.Load(out _).LastWindowEndUtc);

            // A pending window from an earlier build whose section is absent from the next snapshot is dropped too.
            FailedLogonSection.Collect(store, T0.AddMinutes(10), commit: true, CancellationToken.None);
            await Upload(new StubSection("clock", () => new { status = "ok" }));
            Assert.Equal(T0, store.Load(out _).LastWindowEndUtc);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task FailedLogons_AreCollectedOnlyWhenEnabledForTheProfile(bool enabled, bool expected)
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-profile-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "c.json");
        try
        {
            var collector = new SecurityTelemetrySectionCollector(commitFailedLogons: false, enabled, new FailedLogonCursorStore(path));
            var json = JsonSerializer.Serialize(await collector.CollectAsync(new WindowsTelemetryContext(Metadata(), null), CancellationToken.None));
            Assert.Equal(expected, json.Contains("\"failed_logons\"", StringComparison.Ordinal));
            Assert.False(File.Exists(path));
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void FullCircularLog_WithoutMatches_DoesNotLookWrappedNextWindow()
    {
        // saved=100 fell behind the oldest retained record (500): gap, read from 499, nothing matched.
        Assert.Equal(ChannelStart.Gap, FailedLogonCursorLogic.Decide(100, 500, 600, false));
        var saved = FailedLogonCursorLogic.NextSaved(lastRecordId: 499, capped: false, newestBeforeRead: 600);
        Assert.Equal(600, saved);
        Assert.Equal(ChannelStart.Resume, FailedLogonCursorLogic.Decide(saved, 601, 650, false));

        // A real gap after that (oldest beyond previous newest + 1) is still flagged.
        Assert.Equal(ChannelStart.Gap, FailedLogonCursorLogic.Decide(saved, 700, 800, false));
        // A capped read stays at the last handled record; a record read after the bounds were taken wins.
        Assert.Equal(550, FailedLogonCursorLogic.NextSaved(550, capped: true, newestBeforeRead: 600));
        Assert.Equal(610, FailedLogonCursorLogic.NextSaved(610, capped: false, newestBeforeRead: 600));
    }

    [Theory]
    [InlineData("MSSQLSERVER", true)]
    [InlineData("MSSQL$PROD", true)]
    [InlineData("mssql$prod", true)]
    [InlineData("MSSQL$OTHER", false)]
    [InlineData("MSSQLSERVER2", false)]
    [InlineData("Fake", false)]
    [InlineData(null, false)]
    public void SqlEvents_CountOnlyForInstalledServices(string? provider, bool expected)
    {
        var installed = new HashSet<string>(new[] { "MSSQLSERVER", "MSSQL$PROD", "Spooler" }, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(expected, FailedLogonEventReader.IsInstalledSqlProvider(provider, installed));
        Assert.False(FailedLogonEventReader.IsInstalledSqlProvider(provider, new HashSet<string>(StringComparer.OrdinalIgnoreCase)));
    }
}
