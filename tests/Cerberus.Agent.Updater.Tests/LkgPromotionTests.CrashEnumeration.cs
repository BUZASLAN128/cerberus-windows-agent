using System.IO;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed partial class LkgPromotionTests
{
    public static TheoryData<string, string> PromotionCrashStarts =>
        ForEachHostMode("marker", "prepared", "backup", "retire_record", "retire_msi", "move_msi", "retire_manifest",
            "move_manifest", "retire_host", "move_host", "write_record", "write_host", "floor", "journal", "cleanup");

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
        var journal = JournalWithPassedWatch();
        FaultAt(stage, journal);
        if (stage is "marker" or "prepared" or "backup")
            Assert.Equal(original, CanonicalHashes());

        if (stage == "retire_host")
        {
            Assert.False(File.Exists(_store.HostPath));
            Assert.Equal(2, Start(journal, mode, Create()));
            Assert.NotNull(_store.ReadPromotion());
            var installed = Path.Combine(_identity.RuntimeRoot, AgentUpdateLkgStore.UpdaterFileName);
            Assert.True(_store.BootstrapCore(installed, Version, Hash(installed), Now,
                () => { }, path => Assert.Equal(Hash(installed), Hash(path))));
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

        var canonical = CanonicalHashes();
        var floor = Hash(FloorPath);
        var revision = journal.Read().Revision;
        Assert.Equal(0, Start(journal, mode, Create()));
        Assert.Equal(canonical, CanonicalHashes());
        Assert.Equal(floor, Hash(FloorPath));
        Assert.Equal(revision, journal.Read().Revision);
        Assert.Equal(new[] { AgentUpdateLkgStore.UpdaterFileName, "agent.msi", "host.json", "host.lock",
            "lkg.json", "manifest.json", "watch.json" },
            Directory.GetFileSystemEntries(_store.Root).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void InstallerGateFailureDoesNotDispatchOrPin()
    {
        var before = CanonicalHashes();
        var floor = Hash(FloorPath);
        var journal = new LkgSupportJournal(_store.UpdatesRoot);
        journal.Change(_ => _journal with
        {
            Phase = AgentUpdateStates.Failed,
            FailedInstallSequence = AgentUpdateRollbackPolicy.NextFailedInstallSequence(
                0, AgentUpdateErrorCodes.MsiFailed, _plan.Sequence, AgentInstallerHealthPhase.BackendContact),
        });
        var scheduler = new UnchangedWatchTask(_store.HostPath);
        Assert.Equal(0, Start(journal, "--scm-failure", Create(checkpoint: _ =>
            throw new Xunit.Sdk.XunitException("A failed installer gate authorized promotion")), scheduler));
        Assert.Equal(0, journal.Read().FailedInstallSequence);
        Assert.Null(_store.ReadPromotion());
        Assert.Equal(before, CanonicalHashes());
        Assert.Equal(floor, Hash(FloorPath));
        Assert.Equal(0, scheduler.Reads);
        Assert.Equal(0, scheduler.Writes);
    }

    [Fact]
    public void PassedWatchPromotesOnceAndSecondStartOnlyCleansRetiredImage()
    {
        var journal = JournalWithPassedWatch();
        var scheduler = new UnchangedWatchTask(_store.HostPath);
        var probes = 0;
        var promotion = Create(probe: (_, _) => ++probes == 1);

        Assert.Equal(0, Start(journal, "--watch", promotion, scheduler));
        Assert.Equal(Version, journal.Read().HealthyInstalledVersion);
        Assert.Equal(Version, ReadRecordVersion());
        Assert.Equal(1, scheduler.Reads);
        Assert.Equal(0, scheduler.Writes);
        var inventory = LkgInventory();
        Assert.True(File.Exists(Path.Combine(_store.Root, $"retired-{Attempt}.exe")));
        var floor = Hash(FloorPath);
        var revision = journal.Read().Revision;

        Assert.Equal(0, Start(journal, "--watch", promotion, scheduler));
        Assert.Equal(1, probes);
        Assert.Equal(inventory.Where(item => !item.StartsWith($"retired-{Attempt}.exe=", StringComparison.Ordinal)), LkgInventory());
        Assert.Equal(floor, Hash(FloorPath));
        Assert.Equal(revision, journal.Read().Revision);
        // One inventory read per working host start and zero task registration writes.
        Assert.Equal(2, scheduler.Reads);
        Assert.Equal(0, scheduler.Writes);
    }

    [Theory]
    [InlineData("pre-rename")]
    [InlineData("missing-plan")]
    [InlineData("missing-runtime")]
    [InlineData("floor-locked")]
    [InlineData("publish-io")]
    [InlineData("publish-access")]
    public void RetryBoundaryPreservesBytesAndExhaustionAlertsOnce(string failure)
    {
        var old = CanonicalHashes();
        var journal = JournalWithPassedWatch();
        if (failure == "pre-rename")
        {
            var fail = Create(checkpoint: step => { if (step == "backup") throw new IOException("Fixture pre-pivot error."); });
            Assert.False(fail.Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
            Assert.Equal(old, CanonicalHashes());
            Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, journal.Read().WatchOutcomeCode);
            Assert.Equal(AgentUpdateStates.Installed, journal.Read().Phase);
            Assert.Null(_store.ReadPromotion());
            return;
        }

        FaultAt("retire_record", journal);
        var disk = LkgInventory();
        var floorBefore = Hash(FloorPath);
        var retry = Create(runtime: failure == "missing-runtime" ? () => null : null,
            validate: (path, root, missing) =>
            {
                AgentUpdateSecurity.ValidateTrustedPath(path, root, missing);
                if (!path.EndsWith($"retired-{Attempt}.msi", StringComparison.Ordinal)) return;
                if (failure == "publish-io") throw new IOException("Fixture publication sharing error.");
                if (failure == "publish-access") throw new UnauthorizedAccessException("Fixture publication access error.");
            });

        for (var count = 1; count <= AgentUpdateLkgPromotion.MaxRetries; count++)
        {
            using var heldFloor = failure == "floor-locked" ? new FileStream(FloorPath, FileMode.Open, FileAccess.Read, FileShare.None) : null;
            Assert.False(retry.Apply(journal.Read, journal.Change, _watch, failure == "missing-plan" ? null : _plan,
                resume: true, out var handled));
            Assert.Equal(count < AgentUpdateLkgPromotion.MaxRetries, handled);
            Assert.Equal(count, _store.ReadPromotion()!.RetryCount);
            Assert.Equal(disk, LkgInventory());
        }
        var exhausted = journal.Read();
        Assert.Equal(AgentUpdateWatchJournal.CommittedWatch, exhausted.Phase);
        Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, exhausted.AlertCode);
        Assert.Equal(Attempt, exhausted.AlertAttemptId);
        Assert.Equal(floorBefore, Hash(FloorPath));
        Assert.False(retry.Apply(journal.Read, journal.Change, _watch, _plan, resume: true, out var gated));
        Assert.False(gated);
        Assert.Equal(exhausted.Revision, journal.Read().Revision);
        Assert.Single(_logs, code => code == AgentUpdateWatchJournal.LkgPromotionFailed);
    }

    [Fact]
    public void PostFloorCleanupFailureRetriesWithoutChangingSuccessfulJournalAndAcceptsBootstrapHost()
    {
        var journal = JournalWithPassedWatch();
        FaultAt("journal", journal);
        var canonical = CanonicalHashes();
        var floor = Hash(FloorPath);
        var revision = journal.Read().Revision;
        var fail = Create(validate: (path, root, missing) =>
        {
            AgentUpdateSecurity.ValidateTrustedPath(path, root, missing);
            if (!missing && path == MarkerPath) throw new UnauthorizedAccessException("Fixture cleanup denial.");
        });
        Assert.False(fail.Apply(journal.Read, journal.Change, null, null, resume: true));
        Assert.Equal(1, _store.ReadPromotion()!.RetryCount);
        Assert.Equal(canonical, CanonicalHashes());
        Assert.Equal(revision, journal.Read().Revision);
        Assert.Null(journal.Read().FailureCode);

        // Bootstrap repairs the executable without reverting an already committed LKG.
        File.Delete(_store.HostPath);
        var installed = Path.Combine(_identity.RuntimeRoot, AgentUpdateLkgStore.UpdaterFileName);
        Assert.True(_store.BootstrapCore(installed, Version, Hash(installed), Now,
            () => { }, path => Assert.Equal(Hash(installed), Hash(path))));
        Assert.Equal(0, Start(journal, "--watch", Create()));
        Assert.Equal(revision, journal.Read().Revision);
        Assert.Equal(floor, Hash(FloorPath));
        Assert.Equal(Version, ReadRecordVersion());
        Assert.Null(_store.ReadPromotion());
        Assert.DoesNotContain(AgentUpdateWatchJournal.LkgPromotionFailed, _logs);
    }

    [Fact]
    public void RetiredHostCollisionCanBeReenteredAfterBootstrap()
    {
        var journal = JournalWithPassedWatch();
        FaultAt("retire_host", journal);
        var retired = Path.Combine(_store.Root, $"retired-{Attempt}.exe");
        var installed = Path.Combine(_temp.FullName, "bootstrap-source.exe");
        File.Copy(retired, installed);
        Assert.True(_store.BootstrapCore(installed, OldVersion, Hash(installed), Now,
            () => { }, path => Assert.Equal(Hash(installed), Hash(path))));

        Assert.Equal(0, Start(journal, "--watch", Create()));
        Assert.Equal(Version, journal.Read().HealthyInstalledVersion);
        Assert.Equal("new updater", File.ReadAllText(_store.HostPath));
        Assert.Equal("old updater", File.ReadAllText(retired));
        Assert.Null(_store.ReadPromotion());
    }

    [Fact]
    public void PublicationRechecksFinalTempBeforeRenamingCanonicalHostAway()
    {
        var journal = JournalWithPassedWatch();
        var changed = Create(checkpoint: step =>
        {
            if (step == "move_manifest")
                File.WriteAllText(Path.Combine(Stage, AgentUpdateLkgStore.UpdaterFileName), "changed fixture temp");
        });

        Assert.False(changed.Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
        Assert.Equal("old updater", File.ReadAllText(_store.HostPath));
        Assert.False(File.Exists(Path.Combine(_store.Root, $"retired-{Attempt}.exe")));
        Assert.Equal(AgentUpdateLkgPromotion.MaxRetries, _store.ReadPromotion()!.RetryCount);
        Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, journal.Read().AlertCode);
    }

    private string MarkerPath => Path.Combine(_store.Root, AgentUpdateLkgStore.PromotionFileName);
    private string FloorPath => Path.Combine(_store.UpdatesRoot, "rollback-floor.json");
    private string Stage => Path.Combine(_store.Root, "stage-" + Attempt);

    private string[] CanonicalHashes() => new[] { _store.RecordPath, _store.HostRecordPath, _store.MsiPath, _store.ManifestPath, _store.HostPath }
        .Select(Hash).ToArray();

    private string[] LkgInventory() => Directory.EnumerateFiles(_store.Root, "*", SearchOption.AllDirectories)
        .Where(path => path != MarkerPath)
        .Select(path => Path.GetRelativePath(_store.Root, path) + "=" + Hash(path)).Order(StringComparer.Ordinal).ToArray();

    private LkgSupportJournal JournalWithPassedWatch()
    {
        var journal = new LkgSupportJournal(_store.UpdatesRoot);
        journal.Change(_ => _journal);
        AgentUpdateWatchStore.Write(_store.UpdatesRoot, _watch);
        return journal;
    }

    private void FaultAt(string checkpoint, LkgSupportJournal journal)
    {
        var interrupted = Create(checkpoint: step =>
        {
            if (step == checkpoint) throw new OperationCanceledException("Fixture process death at " + checkpoint);
        });
        Assert.Throws<OperationCanceledException>(() => interrupted.Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
    }

    private int Start(LkgSupportJournal journal, string mode, LkgPromotion promotion, UnchangedWatchTask? scheduler = null,
        Action<LkgWatchHostContext, AgentUpdateWatchRecord>? rollback = null)
    {
        Assert.True(AgentUpdateWatchHostArgs.TryParse([mode], out var args));
        var lockPath = Path.Combine(_store.Root, AgentUpdateLkgStore.LockFileName);
        if (!File.Exists(lockPath)) File.WriteAllText(lockPath, "");
        scheduler ??= new UnchangedWatchTask(_store.HostPath);
        var keys = AgentUpdateTrustBuilder.ResolveUpdateManifestPublicKeys(_metadata.ManifestPublicKeysB64, null, null, null, null);
        var work = new LkgWatchHostWork(keys, (path, hash) => Assert.Equal(Hash(path), hash),
            _ => null, (_, _) => { },
            (context, watch) => promotion.Apply(journal.Read, journal.Change, watch, context.Plan, resume: false),
            context =>
            {
                promotion.Apply(journal.Read, journal.Change, context.Watch, context.Plan, resume: true, out var handled);
                return handled;
            },
            store => LkgPromotion.CleanupRetired(store, AgentUpdateSecurity.ValidateTrustedPath),
            rollback ?? ((_, _) => throw new Xunit.Sdk.XunitException("Unexpected rollback in a promotion fixture")));
        return LkgWatchHost.Run(args!, work, new(_store.UpdatesRoot, _store.HostPath, () => true, _ => { },
            path => Assert.Equal(_store.Root, path),
            () => AgentUpdateWatchTask.RegisterWhenNeeded(scheduler, _store.HostPath, allowRepair: true),
            () => Version, _ => true, journal.Change, () => (long)TimeSpan.FromHours(1).TotalMilliseconds));
    }

    private sealed class UnchangedWatchTask(string hostPath) : AgentUpdateWatchTask.ITaskRegistration
    {
        public int Reads { get; private set; }
        public int Writes { get; private set; }
        public AgentUpdateWatchTask.TaskDefinition Read()
        {
            Reads++;
            return new(AgentUpdateWatchTask.BuildXml(hostPath), AgentUpdateWatchTask.TaskSddl, AgentUpdateWatchTask.ServiceAccountLogon);
        }
        public void Register(string xml, int flags, string sddl) => Writes++;
    }
}
