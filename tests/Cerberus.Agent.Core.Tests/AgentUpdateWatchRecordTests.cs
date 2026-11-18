using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateWatchRecordTests : IDisposable
{
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("cerberus-watch-record-");

    [Fact]
    public void WatchRecordUsesPacketFieldNamesAndRoundTrips()
    {
        var root = _root.FullName;
        var path = PreparePath();
        Assert.Null(AgentUpdateWatchStore.Read(root));
        var started = new DateTimeOffset(2026, 11, 18, 12, 0, 0, TimeSpan.Zero);
        var boot = Guid.NewGuid().ToString("N");
        var watch = new AgentUpdateWatchRecord(AgentUpdateWatchRecord.CurrentSchema, Guid.NewGuid().ToString("N"),
            "0.2.1050", 50, Guid.NewGuid(), "0.2.1049", null, started, [new(boot, 1_000)],
            new(boot, 21, started, AgentUpdateWatchServiceState.Running, 0, 0), 0, 0, 2048, started,
            AgentUpdateWatchOutcomes.Open, [AgentUpdateWatchJournal.UnknownPhaseAlert]);

        AgentUpdateWatchStore.Write(root, watch);

        using var json = JsonDocument.Parse(File.ReadAllBytes(path));
        Assert.Equal(AgentUpdateWatchRecord.CurrentSchema, json.RootElement.GetProperty("schema").GetString());
        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("lkg_version").ValueKind);
        Assert.Equal(1_000, json.RootElement.GetProperty("segments")[0].GetProperty("observed_ms").GetInt64());
        var sample = json.RootElement.GetProperty("last_sample");
        Assert.Equal(21, sample.GetProperty("pid").GetInt32());
        Assert.Equal(started, sample.GetProperty("process_start_utc").GetDateTimeOffset());
        Assert.Equal("running", sample.GetProperty("state").GetString());
        Assert.Equal(0, sample.GetProperty("svc_exit").GetInt32());
        Assert.Equal(started, json.RootElement.GetProperty("exe_mtime").GetDateTimeOffset());

        var observed = Assert.IsType<AgentUpdateWatchRecord>(AgentUpdateWatchStore.Read(root));
        Assert.Equal(watch with { Segments = observed.Segments, Alerts = observed.Alerts }, observed);
        Assert.Equal(watch.Segments.ToArray(), observed.Segments.ToArray());
        Assert.Equal(watch.Alerts.ToArray(), observed.Alerts.ToArray());
    }

    [Fact]
    public void IncompleteWatchCannotBeReadAsAnOutcome()
    {
        File.WriteAllText(PreparePath(), """{"schema":"agent.update.watch.v1","outcome":"passed"}""");

        Assert.Throws<InvalidOperationException>(() => AgentUpdateWatchStore.Read(_root.FullName));
    }

    private string PreparePath() => Path.Combine(_root.CreateSubdirectory("lkg").FullName, "watch.json");

    public void Dispose() => _root.Delete(recursive: true);
}
