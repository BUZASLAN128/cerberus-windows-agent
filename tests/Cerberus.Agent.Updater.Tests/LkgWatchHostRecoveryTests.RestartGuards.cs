using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed partial class LkgWatchHostRecoveryTests
{
    [Theory]
    [InlineData(899999, 1, false)]
    [InlineData(900000, 2, true)]
    public void ComposedScmHostWiresWin32LogInstallerEvidenceAndBoundJournalWrite(long uptime, int restartCount, bool recovered)
    {
        File.WriteAllText(Store.HostPath, "fixture canonical image");
        var hostHash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Store.HostPath)));
        AgentUpdateLkgStore.WriteRecord(Store.HostRecordPath, Store.UpdatesRoot, new AgentUpdateLkgHostRecord(
            AgentUpdateLkgStore.HostSchema, "1.2.3", hostHash, "bootstrap", Now, null, null));
        Journal.Change(j => j with { AttemptId = Attempt, Phase = AgentUpdateStates.Installing });
        var restarts = 0;
        var evidenceReads = 0;
        var work = new LkgWatchHostWork([], (_, hash) => Assert.Equal(hostHash, hash),
            _ => throw new Xunit.Sdk.XunitException("Sampled pre-commit"),
            (_, _) => { }, (_, _) => { }, _ => false, _ => { },
            (_, _) => throw new Xunit.Sdk.XunitException("Dispatched rollback"));
        var platform = new LkgWatchHostPlatform(Store.UpdatesRoot, Store.HostPath, () => true,
            scm =>
            {
                Assert.True(scm);
                restarts++;
                throw new Win32Exception(1068);
            }, _ => { }, () => throw new Xunit.Sdk.XunitException("Touched task in pre-commit"), () => null,
            _ => { evidenceReads++; return true; }, Journal.Change, () => uptime);
        Assert.True(AgentUpdateWatchHostArgs.TryParse(["--scm-failure"], out var args));

        Assert.Equal(0, LkgWatchHost.Run(args!, work, platform));
        Assert.Equal(restartCount, restarts);
        Assert.Equal(recovered ? 3 : 0, evidenceReads);
        Assert.Equal(recovered ? AgentUpdateWatchJournal.RollbackFailed : null, Journal.Read().AlertCode);
        var lines = File.ReadAllLines(Path.Combine(Store.UpdatesRoot, "logs", "lkg-host.log"));
        Assert.Equal(restartCount, lines.Count(line => line.EndsWith(" watch_restart_failed win32=" +
            1068.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("revision")]
    [InlineData("precommit-recheck")]
    public void InterruptedRestartPatchRejectsRevisionAndRechecksThePrecommitGuard(string changed)
    {
        var expected = Journal.Change(j => j with { AttemptId = Attempt, Phase = AgentUpdateStates.Installing });
        var current = changed == "revision" ? expected with { Revision = expected.Revision + 1 } :
            expected with { FailureCode = AgentUpdateWatchJournal.RollbackFailed, FailureAttemptId = Attempt };
        var published = false;

        Assert.False(LkgWatchHost.RecordInterruptedRestart(patch =>
        {
            var next = patch(current);
            published = true;
            return next;
        }, expected));
        Assert.False(published);
    }

    [Theory]
    [InlineData("installer-appears", 2)]
    [InlineData("initial-success", 1)]
    [InlineData("non-win32-initial", 1)]
    [InlineData("non-win32-second", 2)]
    public void RestartFallbackRequiresInitialWin32FailureAndRechecksInstallerAfterRetry(string branch, int expectedRestarts)
    {
        Journal.Change(j => j with { AttemptId = Attempt, Phase = AgentUpdateStates.Installing });
        var restarts = 0;
        var ops = Operations() with
        {
            Restart = _ =>
            {
                restarts++;
                if (restarts == 1 && branch == "initial-success") return;
                if (restarts == 1 && branch == "non-win32-initial" || restarts == 2 && branch == "non-win32-second")
                    throw new IOException("fixture non-SCM error");
                throw new Win32Exception(1068);
            },
            NoInstallerActivity = _ => !(branch == "installer-appears" && restarts == 2),
        };
        Assert.Equal(0, LkgWatchHost.Run(Watch, ops));
        Assert.Equal(expectedRestarts, restarts);
        Assert.Null(Journal.Read().AlertCode);
        Assert.Null(Journal.Read().FailureCode);
    }

    [Theory]
    [InlineData("bound")]
    [InlineData("stale-alert")]
    [InlineData("different-code")]
    [InlineData("stale-result")]
    [InlineData("prior-watch")]
    [InlineData("desktop")]
    public void HealthyCommitClearsOnlyTheBoundServerRestartMarker(string branch)
    {
        var plan = new AgentUpdatePlan("msi", "1.2.3", "dev", "fixture", new string('a', 64),
            Now.ToString("O"), "fixture", AttemptId: Attempt, Sequence: 20);
        var before = new AgentUpdateJournal
        {
            AttemptId = Attempt, Phase = AgentUpdateStates.HealthPending,
            WatchAttemptId = branch == "prior-watch" ? Attempt : null,
            FailureCode = branch == "different-code" ? AgentUpdateErrorCodes.InstallOverdue : AgentUpdateWatchJournal.RollbackFailed,
            FailureAttemptId = Attempt, FailureInstallerResultId = branch == "stale-result" ? "old-result" : null,
            AlertCode = AgentUpdateWatchJournal.RollbackFailed, AlertAttemptId = branch == "stale-alert" ? "old-attempt" : Attempt,
        };

        var after = AgentUpdateLocalService.TransitionHealthyInstall(before, plan, Now, serverProfile: branch != "desktop");
        Assert.Equal(branch == "desktop" ? AgentUpdateStates.Installed : AgentUpdateWatchJournal.CommittedWatch, after.Phase);
        Assert.Equal(branch == "bound" ? null : before.AlertCode, after.AlertCode);
        Assert.Equal(branch == "bound" ? null : before.FailureCode, after.FailureCode);
        if (branch == "bound")
        {
            var recovered = AgentUpdateLocalService.CloseRecovery(before with { Phase = AgentUpdateStates.RecoveryRequired },
                plan, healthy: true, Now, serverProfile: true);
            Assert.Null(recovered.AlertCode);
            Assert.Null(recovered.FailureCode);
        }
    }
}
