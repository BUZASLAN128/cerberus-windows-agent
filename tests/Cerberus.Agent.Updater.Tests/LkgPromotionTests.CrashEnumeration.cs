using System.IO;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed partial class LkgPromotionTests
{
    public static TheoryData<string, string> PromotionCrashStarts =>
        ForEachHostMode("a", "b", "c", "d-gap", "d", "e", "f", "g", "h");

    public static TheoryData<string, string> ForwardCrashStarts =>
        ForEachHostMode("launch_requested", "install_may_have_started", "installing", "retryable_busy",
            "pending_reboot", "health_pending", "recovery_required", "committed_watch", "rolling_back");

    private static TheoryData<string, string> ForEachHostMode(params string[] states)
    {
        var rows = new TheoryData<string, string>();
        foreach (var state in states)
        {
            rows.Add(state, "--watch");
            rows.Add(state, "--scm-failure");
        }
        return rows;
    }

    [Theory]
    [MemberData(nameof(ForwardCrashStarts))]
    public void ForwardAndRollbackCrashStatesDispatchWithoutChangingLkgOrFloor(string phase, string mode)
    {
        var hashes = CanonicalHashes();
        var floorPath = Path.Combine(_store.UpdatesRoot, "rollback-floor.json");
        var floor = Hash(floorPath);
        var journal = new LkgSupportJournal(_store.UpdatesRoot);
        journal.Change(_ => _journal with
        {
            Phase = phase,
            RollbackAttemptId = phase == AgentUpdateWatchJournal.RollingBack ? "rollback-owner" : null,
            RollbackStartedUtc = phase == AgentUpdateWatchJournal.RollingBack ? Now.AddMinutes(-31) : null,
        });
        var rolling = phase == AgentUpdateWatchJournal.RollingBack;
        var committed = phase == AgentUpdateWatchJournal.CommittedWatch;
        var sample = _watch with { Outcome = rolling ? AgentUpdateWatchOutcomes.RollbackPending : AgentUpdateWatchOutcomes.Open };
        if (committed || rolling) AgentUpdateWatchStore.Write(_store.UpdatesRoot, sample);
        var events = new List<string>();
        var scheduler = new UnchangedWatchTask(_store.HostPath);
        var work = new LkgWatchHostWork([], (_, _) => { },
            context =>
            {
                Assert.True(committed);
                Assert.Equal(mode == "--scm-failure", context.InvokedByScm);
                events.Add("sample");
                return null;
            },
            (_, _) => throw new Xunit.Sdk.XunitException("Closed an unresolved watch"),
            (_, _) => throw new Xunit.Sdk.XunitException("Promoted without a pass"),
            _ => throw new Xunit.Sdk.XunitException("Resumed without a marker"), _ => { },
            (context, watch) =>
            {
                Assert.True(rolling);
                Assert.True(LkgRollback.SameAuthority(journal.Read(), context.Journal!, watch.AttemptId));
                Assert.Equal("rollback-owner", context.Journal!.RollbackAttemptId);
                events.Add("rollback");
            });
        File.WriteAllText(Path.Combine(_store.Root, AgentUpdateLkgStore.LockFileName), "");
        var before = journal.Read();
        Assert.True(AgentUpdateWatchHostArgs.TryParse([mode], out var args));
        var operations = new LkgWatchHostOperations(() => true,
            scm =>
            {
                Assert.Equal(mode == "--scm-failure", scm);
                events.Add("restart");
            },
            () => LkgWatchHost.VerifySelf(_store, _store.HostPath, _ => { }, (path, hash) =>
            {
                Assert.Equal(Hash(path), hash);
                events.Add("verify");
            }),
            () => LkgWatchHost.ReadSnapshot(_store, journal.Store), () =>
            {
                events.Add("lock");
                return LkgWatchHost.TryLock(_store);
            },
            _ => null, _ => throw new Xunit.Sdk.XunitException("Raised a floor before a pass"),
            () =>
            {
                events.Add("task");
                AgentUpdateWatchTask.RegisterWhenNeeded(scheduler, _store.HostPath, allowRepair: true);
            },
            (state, scm) => LkgWatchHost.Act(_store, journal.Store, state, scm, _logs.Add, work),
            _ => throw new Xunit.Sdk.XunitException("Rewrote an unresolved watch"), _logs.Add);
        Assert.Equal(0, LkgWatchHost.Run(args!, operations));
        Assert.Equal(committed || rolling
            ? new[] { "restart", "verify", "lock", "task", committed ? "sample" : "rollback" }
            : new[] { "restart", "verify" }, events);
        Assert.Equal(before, journal.Read());
        Assert.Equal(hashes, CanonicalHashes());
        Assert.Equal(floor, Hash(floorPath));
        Assert.Equal(0, scheduler.Writes);
    }

    [Theory]
    [MemberData(nameof(PromotionCrashStarts))]
    public void PromotionCrashStagesThroughFullWatchHostStart(string stage, string mode)
    {
        var original = CanonicalHashes();
        var journal = new LkgSupportJournal(_store.UpdatesRoot);
        journal.Change(_ => _journal);
        PlaceCrashState(stage, journal);
        if (stage is "a" or "b")
            Assert.Equal(original, CanonicalHashes());

        if (stage == "d-gap")
        {
            Assert.False(File.Exists(_store.HostPath));
            Assert.Equal(2, Start(journal, mode, Create()));
            Assert.Contains("watch_host_self_check_failed", _logs);
            Assert.NotNull(_store.ReadPromotion());

            // The production bootstrap core can repair the missing canonical executable from the verified source.
            var installed = Path.Combine(_identity.RuntimeRoot, AgentUpdateLkgStore.UpdaterFileName);
            Assert.True(_store.BootstrapCore(installed, Version, Hash(installed), Now,
                () => { }, path => Assert.Equal(Hash(installed), Hash(path))));
        }
        else
        {
            Assert.DoesNotContain("watch_host_self_check_failed", _logs);
        }

        Assert.Equal(0, Start(journal, mode, Create()));
        Assert.Equal(AgentUpdateStates.Installed, journal.Read().Phase);
        Assert.Equal(Version, journal.Read().HealthyInstalledVersion);
        Assert.Equal(Version, ReadRecordVersion());
        Assert.Equal(Version, AgentUpdateRollbackFloor.Read(_store.UpdatesRoot)!.MinVersion);
        Assert.Equal("new updater", File.ReadAllText(_store.HostPath));
        Assert.Equal("new MSI", File.ReadAllText(_store.MsiPath));
        Assert.Equal("new MSI", File.ReadAllText(_plan.ArtifactPath));
        Assert.Null(_store.ReadPromotion());
        Assert.Equal(new[] { AgentUpdateLkgStore.UpdaterFileName, "agent.msi", "host.json", "host.lock",
            "lkg.json", "manifest.json", $"retired-{Attempt}.exe", "watch.json" },
            Directory.GetFileSystemEntries(_store.Root).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray());
    }

    [Theory]
    [InlineData("prepared")]
    [InlineData("published")]
    [InlineData("floor-raised")]
    [InlineData("closed")]
    [InlineData("legacy-published")]
    public void InvalidPromotionRestoresOldStateOrPreservesUnprovableLegacyEvidence(string failure)
    {
        var old = CanonicalHashes();
        var journal = new LkgSupportJournal(_store.UpdatesRoot);
        journal.Change(_ => _journal);
        var stage = failure switch
        {
            "prepared" => "b",
            "floor-raised" => "f",
            "closed" => "g",
            _ => "e",
        };
        PlaceCrashState(stage, journal);
        var backup = Path.Combine(_store.Root, $"retired-{Attempt}.host.json");
        if (failure == "legacy-published") File.Delete(backup);
        File.WriteAllText(failure == "prepared" ? Path.Combine(Stage, "agent.msi") : _store.MsiPath, "fixture incomplete candidate");
        var before = CanonicalHashes();
        var floorBefore = Hash(Path.Combine(_store.UpdatesRoot, "rollback-floor.json"));
        var scheduler = new UnchangedWatchTask(_store.HostPath);

        Assert.Equal(0, Start(journal, "--watch", Create(),
            () => AgentUpdateWatchTask.RegisterWhenNeeded(scheduler, _store.HostPath, allowRepair: true)));
        var failed = journal.Read();
        Assert.Equal(AgentUpdateStates.Installed, failed.Phase);
        Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, failed.WatchOutcomeCode);
        Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, failed.AlertCode);
        Assert.Equal(Attempt, failed.AlertAttemptId);
        Assert.Equal(floorBefore, Hash(Path.Combine(_store.UpdatesRoot, "rollback-floor.json")));
        Assert.Equal(0, scheduler.Writes);
        if (failure == "legacy-published")
        {
            Assert.Equal(before, CanonicalHashes());
            Assert.NotNull(_store.ReadPromotion());
            var next = Path.Combine(_identity.RuntimeRoot, AgentUpdateLkgStore.UpdaterFileName);
            Assert.False(_store.BootstrapCore(next, Version, Hash(next), Now, () => { },
                path => Assert.Equal(_store.HostPath, path)));
        }
        else
        {
            Assert.Equal(old, CanonicalHashes());
            Assert.Null(_store.ReadPromotion());
            if (failure is "floor-raised" or "closed")
            {
                var record = JsonSerializer.Deserialize<AgentUpdateLkgRecord>(
                    File.ReadAllText(_store.RecordPath), AgentUpdateLkgStore.RecordJson)!;
                var keys = AgentUpdateTrustBuilder.ResolveUpdateManifestPublicKeys(
                    _metadata.ManifestPublicKeysB64, null, null, null, null);
                var manifest = AgentUpdateManifestValidator.VerifyStoredSignature(File.ReadAllText(_store.ManifestPath), keys);
                var floor = AgentUpdateRollbackFloor.Read(_store.UpdatesRoot)!;
                Assert.Equal(Version, floor.MinVersion);
                Assert.Throws<InvalidOperationException>(() => AgentUpdateLkgStore.ValidateRelease(record, manifest, OldVersion,
                    floor, new FileInfo(_store.MsiPath).Length, Hash(_store.MsiPath)));
            }
        }
        Assert.Equal(0, Start(journal, "--scm-failure", Create()));
        Assert.Equal(failed.Revision, journal.Read().Revision);
        Assert.Single(_logs, line => line == AgentUpdateWatchJournal.LkgPromotionFailed);
    }

    private string Stage => Path.Combine(_store.Root, "stage-" + Attempt);

    private string[] CanonicalHashes() => new[] { _store.RecordPath, _store.HostRecordPath, _store.MsiPath, _store.ManifestPath, _store.HostPath }
        .Select(Hash).ToArray();

    private void PlaceCrashState(string stage, LkgSupportJournal journal)
    {
        if (stage == "a")
        {
            var installed = Path.Combine(_identity.RuntimeRoot, AgentUpdateLkgStore.UpdaterFileName);
            _store.WritePromotion(new(Attempt, Version, _plan.Sha256, Hash(_store.HostPath), Hash(installed),
                _plan.ManifestDigest!, Path.GetFileName(Stage)));
            return;
        }
        var runtimeReads = 0;
        var prepare = Create(runtime: () => ++runtimeReads == 1 ? _identity : throw new OperationCanceledException());
        Assert.Throws<OperationCanceledException>(() => prepare.Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
        if (stage == "b") return;

        string Retired(string suffix) => Path.Combine(_store.Root, $"retired-{Attempt}{suffix}");
        File.Copy(_store.HostRecordPath, Retired(".host.json"));
        File.Move(_store.RecordPath, Retired(".lkg.json"));
        File.Move(_store.MsiPath, Retired(".msi"));
        File.Move(_store.ManifestPath, Retired(".manifest.json"));
        File.Move(Path.Combine(Stage, "agent.msi"), _store.MsiPath);
        File.Move(Path.Combine(Stage, "manifest.json"), _store.ManifestPath);
        if (stage == "c") return;

        File.Move(_store.HostPath, Retired(".exe"));
        if (stage == "d-gap") return;
        File.Move(Path.Combine(Stage, AgentUpdateLkgStore.UpdaterFileName), _store.HostPath);
        if (stage == "d") return;

        var prepared = Path.Combine(Stage, "lkg.json");
        File.Copy(prepared, _store.RecordPath);
        var record = JsonSerializer.Deserialize<AgentUpdateLkgRecord>(File.ReadAllText(prepared), AgentUpdateLkgStore.RecordJson)!;
        AgentUpdateLkgStore.WriteRecord(_store.HostRecordPath, _store.UpdatesRoot, new AgentUpdateLkgHostRecord(
            AgentUpdateLkgStore.HostSchema, Version, record.UpdaterSha256, "promotion", record.PromotedUtc, Attempt, Version));
        if (stage == "e") return;

        AgentUpdateRollbackFloor.Raise(_store.UpdatesRoot, Version, "watch_pass", record.ManifestSequence,
            record.ManifestDigest, record.PromotedUtc);
        if (stage == "f") return;
        journal.Change(before => before with
        {
            Phase = AgentUpdateStates.Installed, HealthyInstalledVersion = Version, HealthyInstalledSequence = _plan.Sequence,
        });
        if (stage == "h") Assert.True(Create().Apply(journal.Read, journal.Change, null, null, resume: true));
    }

    private int Start(LkgSupportJournal journal, string mode, LkgPromotion promotion, Action? verifyTask = null)
    {
        Assert.True(AgentUpdateWatchHostArgs.TryParse([mode], out var args));
        File.WriteAllText(Path.Combine(_store.Root, AgentUpdateLkgStore.LockFileName), "");
        AgentUpdateWatchStore.Write(_store.UpdatesRoot, _watch);
        var work = new LkgWatchHostWork([], (_, _) => { }, _ => null, (_, _) => { }, (_, _) => { },
            context => promotion.Apply(journal.Read, journal.Change, context.Watch, _plan, resume: true),
            _ => { }, (_, _) => throw new Xunit.Sdk.XunitException("Promotion fixture entered rollback"));
        return LkgWatchHost.Run(args!, new LkgWatchHostOperations(() => true, _ => { },
            () => LkgWatchHost.VerifySelf(_store, _store.HostPath, path => Assert.Equal(_store.Root, path),
                (path, hash) => Assert.Equal(Hash(path), hash)),
            () => LkgWatchHost.ReadSnapshot(_store, journal.Store), () => LkgWatchHost.TryLock(_store),
            _ => new(null), _ => throw new Xunit.Sdk.XunitException("Promotion fixture changed the signed floor"),
            verifyTask ?? (() => { }), (state, scm) => LkgWatchHost.Act(_store, journal.Store, state, scm, _logs.Add, work),
            _ => throw new Xunit.Sdk.XunitException("Promotion fixture rewrote the watch"), _logs.Add));
    }

    private sealed class UnchangedWatchTask(string hostPath) : AgentUpdateWatchTask.ITaskRegistration
    {
        public int Writes { get; private set; }
        public AgentUpdateWatchTask.TaskDefinition Read() => new(AgentUpdateWatchTask.BuildXml(hostPath),
            AgentUpdateWatchTask.TaskSddl, AgentUpdateWatchTask.ServiceAccountLogon);
        public void Register(string xml, int flags, string sddl) => Writes++;
    }
}
