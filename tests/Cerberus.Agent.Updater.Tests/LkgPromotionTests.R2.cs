using System.IO;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed partial class LkgPromotionTests
{
    public static TheoryData<string, bool> FirstPromotionInterruptions
    {
        get
        {
            var rows = new TheoryData<string, bool>();
            foreach (var step in new[] { "move_msi", "move_manifest", "retire_host", "move_host", "write_record", "write_host" })
            {
                rows.Add(step, false);
                rows.Add(step, true);
            }
            return rows;
        }
    }

    [Theory]
    [MemberData(nameof(FirstPromotionInterruptions))]
    public void FirstPromotionRollsForwardAfterDeathOrCaughtIo(string step, bool caughtIo)
    {
        var initialHost = Path.Combine(_temp.FullName, "first-installed-updater.exe");
        File.Copy(_store.HostPath, initialHost);
        foreach (var path in new[] { _store.HostPath, _store.HostRecordPath, _store.RecordPath, _store.MsiPath, _store.ManifestPath, FloorPath })
            File.Delete(path);
        Assert.True(_store.BootstrapCore(initialHost, OldVersion, Hash(initialHost), Now, () => { },
            path => Assert.Equal(Hash(initialHost), Hash(path))));
        Assert.Null(_store.ReadHost()!.LkgVersion);
        Assert.Equal(2, Directory.GetFileSystemEntries(_store.Root).Length);

        var journal = JournalWithPassedWatch();
        var before = journal.Read();
        if (caughtIo)
        {
            var interrupted = Create(checkpoint: point =>
            {
                if (point == step) throw new IOException("Fixture interruption during publication.");
            });
            Assert.False(interrupted.Apply(journal.Read, journal.Change, _watch, _plan, resume: false, out var handled));
            Assert.True(handled);
        }
        else FaultAt(step, journal);

        var pending = _store.ReadPromotion()!;
        Assert.Equal(caughtIo || step != "move_msi", pending.PivotStarted);
        Assert.Equal(caughtIo ? 1 : 0, pending.RetryCount);
        Assert.True(Directory.Exists(Stage));
        Assert.Equal(_plan.Sha256, Hash(_store.MsiPath));
        Assert.Equal(before, journal.Read());
        Assert.False(File.Exists(FloorPath));

        // Apply restarts the publish path from disk. The real host-start gap at retire_host
        // is covered separately through BootstrapCore in PromotionCrashStagesThroughFullWatchHostStart.
        Assert.True(Create().Apply(journal.Read, journal.Change, _watch, _plan, resume: true));
        Assert.Equal(AgentUpdateStates.Installed, journal.Read().Phase);
        Assert.Null(journal.Read().FailureCode);
        Assert.Equal(Version, ReadRecordVersion());
        Assert.Equal(Version, AgentUpdateRollbackFloor.Read(_store.UpdatesRoot)!.MinVersion);
        Assert.Null(_store.ReadPromotion());
    }

    [Fact]
    public void LockedOwnMarkerDefersResumeAndRunThenRollsForward()
    {
        var journal = JournalWithPassedWatch();
        FaultAt("move_msi", journal);
        File.WriteAllText(Path.Combine(_store.Root, AgentUpdateLkgStore.LockFileName), "");
        var before = journal.Read();
        var evidence = LkgInventory();
        var exact = Hash(MarkerPath);
        using (var locked = new FileStream(MarkerPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var read = LkgPromotion.ReadMarkerForRecovery(_store);
            Assert.Equal(LkgPromotion.MarkerState.Invalid, read.State);
            Assert.False(read.Readable);
            Assert.False(Create().Apply(journal.Read, journal.Change, _watch, _plan, resume: true, out var handled));
            Assert.False(handled);
            Assert.Equal(0, Start(journal, "--watch", Create()));
            Assert.Equal(before, journal.Read());
            Assert.Equal(evidence, LkgInventory());
            Assert.Empty(Directory.EnumerateFiles(_store.Root, "promote.stale-*"));
        }
        Assert.Equal(exact, Hash(MarkerPath));
        Assert.Contains(AgentUpdateWatchJournal.LkgPromotionFailed, _logs);
        Assert.Equal(0, Start(journal, "--scm-failure", Create()));
        Assert.Equal(AgentUpdateStates.Installed, journal.Read().Phase);
        Assert.Null(journal.Read().FailureCode);
        Assert.Equal(Version, ReadRecordVersion());
        Assert.False(File.Exists(MarkerPath));
    }

    [Theory]
    [InlineData("stage")]
    [InlineData("retired")]
    public void AbsentMarkerWithExactCurrentAttemptEvidenceDefersAndPreservesIt(string kind)
    {
        var journal = JournalWithPassedWatch();
        var before = journal.Read();
        var retired = Path.Combine(_store.Root, $"retired-{Attempt}.exe");
        if (kind == "stage") Directory.CreateDirectory(Stage);
        else File.WriteAllText(retired, "current attempt retired executable");
        Assert.Equal(LkgPromotion.MarkerState.Absent, LkgPromotion.ReadMarkerForRecovery(_store).State);
        Assert.Equal(0, Start(journal, "--watch", Create(runtime: () => null)));
        Assert.Equal(before, journal.Read());
        Assert.True(kind == "stage" ? Directory.Exists(Stage) : File.Exists(retired));
        Assert.False(File.Exists(MarkerPath));
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("malformed")]
    public void NoMarkerAuthorityWithClearCurrentAttemptAllowsTerminalClose(string markerState)
    {
        var journal = JournalWithPassedWatch();
        File.WriteAllText(Path.Combine(_store.Root, $"retired-{Attempt}-extension.exe"), "belongs to a different attempt");
        if (markerState == "malformed") File.WriteAllText(MarkerPath, "{");
        Assert.False(Create(runtime: () => null).Apply(journal.Read, journal.Change, _watch, _plan, resume: false, out var handled));
        Assert.True(handled);
        Assert.Equal(AgentUpdateStates.Installed, journal.Read().Phase);
        Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, journal.Read().FailureCode);
        Assert.Equal(Attempt, journal.Read().AlertAttemptId);
        Assert.Equal(markerState == "malformed", File.Exists(MarkerPath));
    }

    [Theory]
    [InlineData("evidence-appears")]
    [InlineData("read-denied")]
    public void StaleArchiveRechecksCurrentEvidenceAndNeverArchivesAnIoRead(string branch)
    {
        var journal = JournalWithPassedWatch();
        _store.WritePromotion(OlderMarker());
        var exact = Hash(MarkerPath);
        var before = journal.Read();
        var markerReads = 0;
        var promotion = Create(runtime: () =>
        {
            if (branch == "evidence-appears") Directory.CreateDirectory(Stage);
            return _identity;
        }, validate: (path, root, missing) =>
        {
            AgentUpdateSecurity.ValidateTrustedPath(path, root, missing);
            if (branch == "read-denied" && path == MarkerPath && ++markerReads == 1)
                throw new IOException("Fixture marker read failed before archiving.");
        });
        Assert.False(promotion.Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
        Assert.Equal(before, journal.Read());
        Assert.Equal(exact, Hash(MarkerPath));
        Assert.Equal(OldVersion, ReadRecordVersion());
        Assert.Empty(Directory.EnumerateFiles(_store.Root, "promote.stale-*"));
    }

    [Fact]
    public void FailureWithNewlyUnreadableMarkerRechecksEvidenceBeforeClosing()
    {
        var journal = JournalWithPassedWatch();
        var before = journal.Read();
        FileStream? locked = null;
        try
        {
            var promotion = Create(probe: (_, _) =>
            {
                locked = new FileStream(MarkerPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                return false;
            });
            Assert.False(promotion.Apply(journal.Read, journal.Change, _watch, _plan, resume: false, out var handled));
            Assert.False(handled);
            Assert.Equal(before, journal.Read());
            Assert.True(Directory.Exists(Stage));
        }
        finally { locked?.Dispose(); }
        Assert.False(_store.ReadPromotion()!.PivotStarted);
        Assert.True(Create().Apply(journal.Read, journal.Change, _watch, _plan, resume: true));
        Assert.Equal(Version, ReadRecordVersion());
    }

    [Fact]
    public void MalformedOwnedMarkerWaitsForRealWatchEscapeAndNextPromotion()
    {
        var journal = JournalWithPassedWatch();
        FaultAt("move_msi", journal);
        File.WriteAllText(Path.Combine(_store.Root, AgentUpdateLkgStore.LockFileName), "");
        File.WriteAllText(MarkerPath, "{ fixture malformed owned marker");
        var exact = File.ReadAllBytes(MarkerPath);
        var digest = Hash(MarkerPath);
        var before = journal.Read();
        var evidence = LkgInventory();
        Assert.Equal(0, Start(journal, "--watch", Create()));
        Assert.Equal(before, journal.Read());
        Assert.Equal(evidence, LkgInventory());
        Assert.Equal(exact, File.ReadAllBytes(MarkerPath));
        Assert.Empty(Directory.EnumerateFiles(_store.Root, "promote.stale-*"));
        Assert.Contains(AgentUpdateWatchJournal.LkgPromotionFailed, _logs);

        var watchPath = Path.Combine(_store.Root, AgentUpdateWatchStore.FileName);
        File.SetLastWriteTimeUtc(watchPath, Now.UtcDateTime);
        Assert.Equal(before, AgentUpdateLocalService.ObservePostCommitWatch(_store.UpdatesRoot, before, Now.AddHours(26).AddTicks(-1)));
        var after = journal.Change(active => AgentUpdateLocalService.ObservePostCommitWatch(_store.UpdatesRoot, active, Now.AddHours(26)));
        Assert.Equal(AgentUpdateStates.Installed, after.Phase);
        Assert.Equal(AgentUpdateWatchJournal.WatchUnavailable, after.WatchOutcomeCode);
        Assert.Equal(Attempt, after.WatchOutcomeAttemptId);

        const string nextAttempt = "next-watched-attempt";
        var installed = Path.Combine(_identity.RuntimeRoot, AgentUpdateLkgStore.UpdaterFileName);
        var installedHash = Hash(installed);
        Assert.True(_store.BootstrapCore(installed, Version, installedHash, Now.AddHours(27),
            () => { }, path => Assert.Equal(installedHash, Hash(path)), "next-fixture-campaign",
            (version, hash) => version == Version && hash == installedHash));
        Assert.Equal("bootstrap_repair", _store.ReadHost()!.PlacedBy);
        Assert.Equal(exact, File.ReadAllBytes(MarkerPath));
        AssertMixedLkgRefusesRollback(journal, after);

        var directory = Directory.CreateDirectory(Path.Combine(_store.UpdatesRoot, "attempts", "attempt-" + nextAttempt)).FullName;
        var msi = Path.Combine(directory, AgentUpdateSecurity.ArtifactFileName);
        var manifest = Path.Combine(directory, AgentUpdateSecurity.ManifestFileName);
        File.Copy(_plan.ArtifactPath, msi);
        File.Copy(_plan.ManifestPath!, manifest);
        var nextPlan = _plan with { AttemptId = nextAttempt, ArtifactPath = msi, ManifestPath = manifest };
        AgentUpdateDurableFile.Write(Path.Combine(directory, AgentUpdateSecurity.PlanFileName), _store.UpdatesRoot, nextPlan);
        AgentUpdateWatchStore.Write(_store.UpdatesRoot, _watch with { AttemptId = nextAttempt });
        journal.Change(_ => _journal with { AttemptId = nextAttempt, WatchAttemptId = nextAttempt, WatchRequestedUtc = Now.AddHours(27) });
        Assert.Equal(0, Start(journal, "--watch", Create()));
        Assert.Equal(AgentUpdateStates.Installed, journal.Read().Phase);
        Assert.Equal(nextAttempt, journal.Read().AttemptId);
        Assert.Equal(Version, ReadRecordVersion());
        Assert.Equal(exact, File.ReadAllBytes(Path.Combine(_store.Root, "promote.stale-" + digest + ".json")));
        Assert.False(File.Exists(MarkerPath));
    }

    private void AssertMixedLkgRefusesRollback(LkgSupportJournal journal, AgentUpdateJournal installed)
    {
        // A hypothetical pending rollback reads the same mixed on-disk set. Give only its
        // transition an in-memory journal seam; the real closed journal stays installed.
        var rolling = installed with
        {
            Phase = AgentUpdateWatchJournal.RollingBack, RollbackAttemptId = "fixture-rollback",
            RollbackStartedUtc = DateTimeOffset.UtcNow.AddHours(-1),
        };
        var watch = _watch with { Outcome = AgentUpdateWatchOutcomes.RollbackPending };
        var sample = new AgentUpdateWatchSample("fixture-boot", 1, Now, AgentUpdateWatchServiceState.Running, 0, 0, false, false, false);
        var runtime = new LkgWatchRuntimeIdentity(Version, _identity.ProductCode, _identity.ServiceExeSha256, _identity.RuntimeRoot);
        var native = new LkgWatchHostObservation(sample.BootId, 1, Now, Version, rolling.LifecycleGeneration, sample, runtime, true, true, null, null);
        var context = new LkgWatchHostContext(_store, journal.Store, rolling, watch, _plan, true, true, _logs.Add);
        var keys = AgentUpdateTrustBuilder.ResolveUpdateManifestPublicKeys(_metadata.ManifestPublicKeysB64, null, null, null, null);
        Assert.False(File.Exists(_store.RecordPath));
        Assert.Equal(_plan.Sha256, Hash(_store.MsiPath));
        Assert.Throws<InvalidOperationException>(() => _store.Validate(OldVersion, keys, "dev", Pin, false));
        var before = LkgInventory();
        var admissions = 0;
        var launches = 0;
        var restarts = 0;
        var transitioned = rolling;
        LkgRollback.RunCore(context, rolling, watch, native, (store, replaced) =>
        {
            admissions++;
            Assert.Equal(OldVersion, replaced);
            return LkgWatchHostBinding.ReadEligibleLkg(store, _metadata, keys, replaced);
        }, _ => throw new Xunit.Sdk.XunitException("Queried MSI product state after admission refusal."),
            (_, _, _, _) => launches++, new(patch => transitioned = patch(transitioned), () => { }, () => restarts++));
        Assert.Equal(1, admissions);
        Assert.Equal(0, launches);
        Assert.Equal(1, restarts);
        Assert.Equal(AgentUpdateStates.Failed, transitioned.Phase);
        Assert.Equal(AgentUpdateWatchJournal.RollbackFailed, transitioned.FailureCode);
        Assert.Equal(Attempt, transitioned.FailureAttemptId);
        var record = AgentUpdateWatchStore.Read(_store.UpdatesRoot)!;
        Assert.Equal(Attempt, record.AttemptId);
        Assert.Equal(AgentUpdateWatchOutcomes.RollbackFailed, record.Outcome);
        Assert.Contains(AgentUpdateWatchJournal.RollbackFailed, record.Alerts);
        Assert.Contains(AgentUpdateWatchJournal.RollbackFailed, _logs);
        Assert.Equal(installed, journal.Read());
        Assert.Equal(before.Where(entry => !entry.StartsWith("watch.json=", StringComparison.Ordinal)),
            LkgInventory().Where(entry => !entry.StartsWith("watch.json=", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AmbiguousPrePivotRetentionDoesNotStampRetryAndNextClearReadCleans(bool terminalCleanup)
    {
        var journal = JournalWithPassedWatch();
        if (terminalCleanup)
        {
            var deniedCleanup = Create(probe: (_, _) => false, validate: (path, root, missing) =>
            {
                AgentUpdateSecurity.ValidateTrustedPath(path, root, missing);
                if (path == MarkerPath && !missing) throw new UnauthorizedAccessException("Fixture cleanup denial.");
            });
            Assert.Throws<UnauthorizedAccessException>(() =>
                deniedCleanup.Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
            Assert.Equal(AgentUpdateStates.Installed, journal.Read().Phase);
            Assert.True(Directory.Exists(Stage));
        }
        else FaultAt("marker", journal);

        var exact = Hash(MarkerPath);
        var before = journal.Read();
        var denyEvidence = Create(runtime: () => null, validate: (path, root, missing) =>
        {
            AgentUpdateSecurity.ValidateTrustedPath(path, root, missing);
            if (Path.GetFileName(path) == $"retired-{Attempt}.lkg.json")
                throw new IOException("Fixture cannot inspect the pivot evidence.");
        });
        Assert.False(denyEvidence.Apply(journal.Read, journal.Change, _watch, _plan, resume: true, out var handled));
        Assert.False(handled);
        Assert.Equal(before, journal.Read());
        Assert.Equal(exact, Hash(MarkerPath));
        Assert.False(_store.ReadPromotion()!.PivotStarted);
        Assert.Equal(0, _store.ReadPromotion()!.RetryCount);

        Assert.False(Create(runtime: () => null).Apply(journal.Read, journal.Change, _watch, _plan, resume: true));
        Assert.Equal(AgentUpdateStates.Installed, journal.Read().Phase);
        Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, journal.Read().AlertCode);
        Assert.Equal(Attempt, journal.Read().AlertAttemptId);
        Assert.False(Directory.Exists(Stage));
        Assert.False(File.Exists(MarkerPath));
        Assert.Equal(OldVersion, ReadRecordVersion());
    }

    [Theory]
    [InlineData("legacy")]
    [InlineData("attempt")]
    [InlineData("watch-attempt")]
    [InlineData("watch-request")]
    [InlineData("phase")]
    public void NonOwnerCannotConsumeAValidPromotionMarker(string branch)
    {
        var journal = JournalWithPassedWatch();
        FaultAt("prepared", journal);
        var marker = _store.ReadPromotion()!;
        if (branch == "legacy") _store.WritePromotion(marker with { PivotStarted = null, RetryCount = null });
        var changed = journal.Read() with
        {
            AttemptId = branch == "attempt" ? "other-attempt" : Attempt,
            WatchAttemptId = branch == "watch-attempt" ? "other-watch" : Attempt,
            WatchRequestedUtc = branch == "watch-request" ? null : Now,
            Phase = branch == "phase" ? AgentUpdateStates.Failed :
                branch == "attempt" ? AgentUpdateStates.Installed : AgentUpdateWatchJournal.CommittedWatch,
            FailureCode = branch == "attempt" ? AgentUpdateWatchJournal.LkgPromotionFailed : null,
            FailureAttemptId = branch == "attempt" ? Attempt : null,
        };
        var exact = Hash(MarkerPath);
        var before = CanonicalHashes();
        var result = changed;
        var reached = 0;
        Assert.False(Create(runtime: () => { reached++; return _identity; }).Apply(() => result,
            patch => result = patch(result), _watch, _plan, resume: true, out var handled));
        Assert.False(handled);
        Assert.Equal(0, reached);
        Assert.Equal(exact, Hash(MarkerPath));
        Assert.Equal(before, CanonicalHashes());
        Assert.True(Directory.Exists(Stage));
        Assert.Equal(changed.Phase, result.Phase);
        if (branch != "attempt")
        {
            Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, result.AlertCode);
            Assert.Equal(Attempt, result.AlertAttemptId);
        }
    }

    [Theory]
    [InlineData("inline-success")]
    [InlineData("restore")]
    [InlineData("hash-mismatch")]
    [InlineData("existing-canonical")]
    public void SecondHostRenameRetriesThenOnlyRestoresTheExactOldHostWithoutOverwrite(string branch)
    {
        var journal = JournalWithPassedWatch();
        var pendingHost = Path.Combine(Stage, AgentUpdateLkgStore.UpdaterFileName);
        var retiredHost = Path.Combine(_store.Root, $"retired-{Attempt}.exe");
        var old = Hash(_store.HostPath);
        var before = journal.Read();
        var floor = Hash(FloorPath);
        var attempts = 0;
        var waits = new List<TimeSpan>();
        FileStream? moveBlock = null;
        try
        {
            var promotion = Create(checkpoint: point =>
            {
                if (point != "before_move_host") return;
                attempts++;
                // Deny delete sharing on the real prepared entry. Both retries run the real File.Move.
                moveBlock ??= new FileStream(pendingHost, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (attempts == 3 && branch == "hash-mismatch") File.WriteAllText(retiredHost, "substitute fixture image");
                if (attempts == 3 && branch == "existing-canonical") File.WriteAllText(_store.HostPath, "unrelated fixture image");
            }, delayHostMove: delay =>
            {
                waits.Add(delay);
                if (branch == "inline-success" && waits.Count == 2) moveBlock!.Dispose();
            });
            Assert.Equal(branch == "inline-success", promotion.Apply(journal.Read, journal.Change, _watch, _plan, resume: false));
        }
        finally { moveBlock?.Dispose(); }
        Assert.Equal(3, attempts);
        Assert.Equal(new[] { TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2) }, waits);

        if (branch != "inline-success")
        {
            Assert.Equal(floor, Hash(FloorPath));
            Assert.Equal(AgentUpdateWatchJournal.CommittedWatch, journal.Read().Phase);
            Assert.Null(journal.Read().FailureCode);
            Assert.Equal(1, _store.ReadPromotion()!.RetryCount);
            Assert.Equal(_plan.Sha256, Hash(_store.MsiPath));
            if (branch == "hash-mismatch" || branch == "existing-canonical")
            {
                if (branch == "hash-mismatch") Assert.False(File.Exists(_store.HostPath));
                else Assert.Equal("unrelated fixture image", File.ReadAllText(_store.HostPath));
                Assert.True(File.Exists(retiredHost));
                Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, journal.Read().AlertCode);
                Assert.Equal(Attempt, journal.Read().AlertAttemptId);
                Assert.Single(_logs, code => code == AgentUpdateWatchJournal.LkgPromotionFailed);
                return;
            }
            Assert.Equal(old, Hash(_store.HostPath));
            Assert.False(File.Exists(retiredHost));
            Assert.Equal(before, journal.Read());
            Assert.Equal(0, Start(journal, "--watch", Create()));
        }
        Assert.Equal(AgentUpdateStates.Installed, journal.Read().Phase);
        Assert.Equal(Version, ReadRecordVersion());
        Assert.Equal("new updater", File.ReadAllText(_store.HostPath));
        Assert.False(File.Exists(MarkerPath));
    }
}
