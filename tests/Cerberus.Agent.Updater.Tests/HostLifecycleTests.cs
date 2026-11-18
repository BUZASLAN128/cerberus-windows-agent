using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;

namespace Cerberus.Agent.Updater.Tests;

public sealed class HostLifecycleTests : IDisposable
{
    private const string Attempt = "ddd488d739e54ffa826c23b8b17fc278";
    private static readonly DateTimeOffset Now = new(2026, 11, 18, 13, 0, 0, TimeSpan.Zero);
    private static readonly AgentUpdateWatchHostArgs Watch = new(AgentUpdateWatchHostMode.Watch, null);
    private static readonly AgentUpdateWatchHostArgs Scm = new(AgentUpdateWatchHostMode.ScmFailure, null);
    private static readonly LkgWatchHostSnapshot Idle = new(null, null, false, false, false);
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("cerberus-host-lane-");
    private string Root => _root.FullName;
    private AgentUpdateLkgStore Store => new(Root);

    [Fact]
    public void ScmRestartPrecedesSelfCheckFailureAndDoesNotEnterWork()
    {
        var events = new List<string>();
        var ops = Baseline() with
        {
            Restart = scm => events.Add(scm ? "scm_restart" : "watch_restart"),
            VerifyHost = () => { events.Add("verify"); throw new InvalidOperationException(); },
            Log = events.Add,
        };
        Assert.Equal(2, LkgWatchHost.Run(Scm, ops));
        Assert.Equal(["scm_restart", "verify", "watch_host_self_check_failed"], events);
    }

    [Fact]
    public void HostLockContentionAllowsOnlyTheEarlierRestartStep()
    {
        _root.CreateSubdirectory("lkg");
        var path = Path.Combine(Store.Root, AgentUpdateLkgStore.LockFileName);
        File.WriteAllText(path, "");
        using var owner = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var events = new List<string>();
        var ops = Baseline() with
        {
            Restart = _ => events.Add("restart"),
            VerifyHost = () => events.Add("verify"),
            ReadSnapshot = () => Idle with { PromotionPending = true },
            TryLock = () => { events.Add("lock"); return LkgWatchHost.TryLock(Store); },
        };
        Assert.Equal(0, LkgWatchHost.Run(Scm, ops));
        Assert.Equal(["restart", "verify", "lock"], events);
    }

    [Fact]
    public void AThousandIdleStartsLeaveTheFixtureInventoryUnchanged()
    {
        _root.CreateSubdirectory("lkg");
        var before = Inventory();
        var ops = Baseline() with { Log = new LkgHostLog(Root).Write };
        for (var i = 0; i < 1_000; i++)
            Assert.Equal(0, LkgWatchHost.Run(Watch, ops));
        Assert.Equal(before, Inventory());
    }

    [Fact]
    public void IdleSignedFloorRequiresAnExistingHostLockAndWritesOnlyTheFloor()
    {
        _root.CreateSubdirectory("lkg");
        var candidate = new LkgSignedFloor.Candidate("0.2.1048", 50, new('a', 64));
        var ops = Baseline() with
        {
            InspectFloor = _ => new(candidate),
            TryLock = () => LkgWatchHost.TryLock(Store),
            ApplyFloor = floor => Assert.True(LkgSignedFloor.Apply(Root, floor, Now)),
        };
        var before = Inventory();
        Assert.Equal(0, LkgWatchHost.Run(Watch, ops));
        Assert.Equal(before, Inventory());

        File.WriteAllText(Path.Combine(Store.Root, AgentUpdateLkgStore.LockFileName), "");
        before = Inventory();
        Assert.Equal(0, LkgWatchHost.Run(Watch, ops));
        Assert.Equal("0.2.1048", AgentUpdateRollbackFloor.Read(Root)!.MinVersion);
        Assert.Equal(before.Append("rollback-floor.json").Order().ToArray(), Inventory());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnknownPhaseWritesOnlyAnAlertBoundToAnExistingWatch(bool hasWatch)
    {
        _root.CreateSubdirectory("lkg");
        File.WriteAllText(Path.Combine(Store.Root, AgentUpdateLkgStore.LockFileName), "");
        var watch = hasWatch ? new AgentUpdateWatchRecord(AgentUpdateWatchRecord.CurrentSchema, Attempt,
            "0.2.1050", 50, Guid.NewGuid(), null, null, Now, [], null, 0, 0, null, null,
            AgentUpdateWatchOutcomes.Open, []) : null;
        if (watch is not null)
            AgentUpdateWatchStore.Write(Root, watch);
        var codes = new List<string>();
        var ops = Baseline() with
        {
            ReadSnapshot = () => new(new AgentUpdateJournal { AttemptId = Attempt, Phase = "future_phase" }, watch, true, false, false),
            TryLock = () => LkgWatchHost.TryLock(Store),
            WriteWatch = value => AgentUpdateWatchStore.Write(Root, value),
            Log = codes.Add,
        };
        Assert.Equal(0, LkgWatchHost.Run(Watch, ops));
        Assert.Equal([AgentUpdateWatchJournal.UnknownPhaseAlert], codes);
        var reloaded = AgentUpdateWatchStore.Read(Root);
        if (hasWatch) Assert.Equal([AgentUpdateWatchJournal.UnknownPhaseAlert], reloaded!.Alerts);
        else Assert.Null(reloaded);
    }

    [Fact]
    public void UnsignedOrUnboundFloorDoesNotRaiseAndMatchingSignedFloorRaisesOnce()
    {
        using var rsa = RSA.Create(2048);
        var dir = _root.CreateSubdirectory(Path.Combine("attempts", "attempt-" + Attempt));
        var manifestPath = Path.Combine(dir.FullName, AgentUpdateSecurity.ManifestFileName);
        var unsigned = new AgentUpdateManifest("msi", "0.2.1050", "dev", "https://example.invalid/package.msi",
            new('a', 64), "test", "2026-05-01T00:00:00Z", "1", false, "", AgentUpdateManifest.V2SchemaVersion,
            50, "2026-05-08T00:00:00Z", 1024, "test-pin") { MinRollbackVersion = "0.2.1048" };
        var signed = unsigned with { Signature = Convert.ToBase64String(rsa.SignData(
            Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(unsigned)),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) };
        var plan = new AgentUpdatePlan("msi", signed.Version, signed.Channel,
            Path.Combine(dir.FullName, AgentUpdateSecurity.ArtifactFileName), signed.Sha256, Now.ToString("O"), "support",
            AttemptId: Attempt, Sequence: 50, ManifestPath: manifestPath, ManifestDigest: AgentUpdateManifestValidator.Digest(signed));
        AgentUpdateDurableFile.Write(Path.Combine(dir.FullName, AgentUpdateSecurity.PlanFileName), Root, plan);
        var readPlan = LkgSignedFloor.ReadPlan(Root, Attempt);
        IReadOnlyList<string> keys = [rsa.ExportSubjectPublicKeyInfoPem()];

        File.WriteAllText(manifestPath, JsonSerializer.Serialize(unsigned));
        Assert.Throws<InvalidOperationException>(() => LkgSignedFloor.Inspect(Root, readPlan, signed.Version, keys));
        Assert.Null(AgentUpdateRollbackFloor.Read(Root));

        File.WriteAllText(manifestPath, JsonSerializer.Serialize(signed));
        Assert.Null(LkgSignedFloor.Inspect(Root, readPlan, "0.2.1049", keys));
        Assert.Throws<InvalidOperationException>(() => LkgSignedFloor.Inspect(Root, readPlan! with { Sequence = 51 }, signed.Version, keys));
        var candidate = Assert.IsType<LkgSignedFloor.Candidate>(LkgSignedFloor.Inspect(Root, readPlan, signed.Version, keys)?.Pending);
        Assert.True(LkgSignedFloor.Apply(Root, candidate, Now));
        Assert.Null(LkgSignedFloor.Inspect(Root, readPlan, signed.Version, keys)!.Pending);
        Assert.Equal("0.2.1048", AgentUpdateRollbackFloor.Read(Root)!.MinVersion);
    }

    [Fact]
    public void LogRotatesOnlyOnceAtTheBound()
    {
        var logs = _root.CreateSubdirectory("logs");
        var path = Path.Combine(logs.FullName, "lkg-host.log");
        using (var stream = File.Create(path))
            stream.SetLength(LkgHostLog.MaximumBytes);
        new LkgHostLog(Root).Write("watch_host_action_failed");
        Assert.Equal(LkgHostLog.MaximumBytes, new FileInfo(Path.Combine(logs.FullName, "lkg-host.1.log")).Length);
        Assert.Contains("watch_host_action_failed", File.ReadAllText(path));
        Assert.Equal(2, logs.GetFiles().Length);
    }

    private string[] Inventory() => Directory.EnumerateFileSystemEntries(Root, "*", SearchOption.AllDirectories)
        .Select(path => Path.GetRelativePath(Root, path)).Order().ToArray();

    private static LkgWatchHostOperations Baseline() => new(
        () => true,
        _ => { },
        () => { },
        () => Idle,
        () => throw new Xunit.Sdk.XunitException("Unexpected lock attempt"),
        _ => null,
        _ => throw new Xunit.Sdk.XunitException("Unexpected floor write"),
        () => throw new Xunit.Sdk.XunitException("Unexpected task verification"),
        (_, _) => throw new Xunit.Sdk.XunitException("Unexpected action"),
        _ => throw new Xunit.Sdk.XunitException("Unexpected watch write"),
        code => throw new Xunit.Sdk.XunitException("Unexpected log " + code));

    public void Dispose() => _root.Delete(recursive: true);
}
