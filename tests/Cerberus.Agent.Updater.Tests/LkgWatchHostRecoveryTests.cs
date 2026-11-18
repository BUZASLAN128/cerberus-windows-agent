using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed partial class LkgWatchHostRecoveryTests : IDisposable
{
    private const string Attempt = "forward-attempt";
    private static readonly DateTimeOffset Now = DateTimeOffset.UnixEpoch.AddHours(24);
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("cerberus-host-recovery-");
    private AgentUpdateLkgStore Store => new(_root.FullName);
    private LkgSupportJournal Journal => new(_root.FullName);
    private AgentUpdateWatchHostArgs Watch => new(AgentUpdateWatchHostMode.Watch, null);
    private List<string> Events { get; } = [];

    public LkgWatchHostRecoveryTests()
    {
        _root.CreateSubdirectory("lkg");
        File.WriteAllText(Path.Combine(Store.Root, AgentUpdateLkgStore.LockFileName), "");
    }

    [Fact]
    public void SilentProbeTimesOutAndReleasesHostLock()
    {
        var pipeName = "cerberus-silent-probe-" + Guid.NewGuid().ToString("N");
        using var ready = new NamedPipeServerStream(pipeName, PipeDirection.In, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        var script = Path.Combine(_root.FullName, "silent.ps1");
        File.WriteAllText(script, """
            param($PipeName)
            $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $PipeName, [IO.Pipes.PipeDirection]::Out)
            try {
                $pipe.Connect(30000)
                Start-Sleep -Seconds 30
            } finally { $pipe.Dispose() }
            """);
        Process? child = null;
        var elapsed = new Stopwatch();
        var timeout = TimeSpan.FromSeconds(4);
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        {
            UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true,
            StandardOutputEncoding = new ProbeStartupEncoding(ObserveStartup),
            ArgumentList = { "-NoProfile", "-NonInteractive", "-File", script, pipeName },
        };
        Journal.Change(j => j with { AttemptId = Attempt, Phase = AgentUpdateWatchJournal.CommittedWatch });
        var ops = Operations() with
        {
            Act = (_, _) =>
            {
                Assert.Null(LkgWatchHost.TryLock(Store));
                Assert.False(LkgProbe.Run(start, "probe", "1.2.3", 1, timeout));
            },
        };
        try
        {
            var result = LkgWatchHost.Run(Watch, ops);
            Assert.True(child is not null, $"The silent probe did not start (watch host exit {result}).");
            Assert.Equal(0, result);
            var duration = elapsed.Elapsed;
            Assert.True(duration >= timeout - TimeSpan.FromMilliseconds(250) && duration < TimeSpan.FromSeconds(10), duration.ToString());
            using var released = LkgWatchHost.TryLock(Store);
            Assert.NotNull(released);
            Assert.True(child.WaitForExit(1_000), "The timed-out silent probe was still alive.");
        }
        finally
        {
            using (child)
            {
                if (child is not null && !child.HasExited)
                {
                    child.Kill();
                    child.WaitForExit(1_000);
                }
            }
        }

        void ObserveStartup()
        {
            using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try { ready.WaitForConnectionAsync(startup.Token).GetAwaiter().GetResult(); }
            catch (OperationCanceledException)
            {
                throw new Xunit.Sdk.XunitException("The silent probe did not reach its startup pipe within 30 seconds.");
            }
            Assert.True(GetNamedPipeClientProcessId(ready.SafePipeHandle, out var pid),
                "The startup pipe did not identify the silent probe process.");
            child = Process.GetProcessById(checked((int)pid));
            _ = child.SafeHandle;
            Assert.False(child.HasExited);
            elapsed.Start();
        }
    }

    // Process.Start constructs the redirected stdout reader before LkgProbe starts its timeout.
    private sealed class ProbeStartupEncoding(Action observeStartup) : UTF8Encoding
    {
        public override Decoder GetDecoder()
        {
            observeStartup();
            return base.GetDecoder();
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint processId);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RepairAndAlertPersistenceFailuresStillDispatchDueRollback(bool alertWriteFails)
    {
        var journal = Journal.Change(j => j with
        {
            AttemptId = Attempt, Phase = AgentUpdateWatchJournal.RollingBack,
            WatchAttemptId = Attempt, WatchRequestedUtc = Now,
            RollbackAttemptId = "rollback-attempt", RollbackStartedUtc = Now,
        });
        var watch = new AgentUpdateWatchRecord(AgentUpdateWatchRecord.CurrentSchema, Attempt, "1.2.3", 20,
            Guid.NewGuid(), "1.2.2", "1.2.2", Now, [], null, 0, 0, null, null,
            AgentUpdateWatchOutcomes.RollbackPending, []);
        AgentUpdateWatchStore.Write(Store.UpdatesRoot, watch);
        var work = new LkgWatchHostWork([], (_, _) => { }, _ => throw new Xunit.Sdk.XunitException("Sampled a rollback"),
            (_, _) => { }, (_, _) => { }, _ => false, _ => { },
            (context, record) =>
            {
                Assert.True(LkgRollback.SameAuthority(Journal.Read(), journal, record.AttemptId));
                Assert.Equal(Now, context.Journal!.RollbackStartedUtc);
                Assert.Equal(!alertWriteFails, record.Alerts.Contains("watch_task_repair_failed"));
                Events.Add("rollback");
            });
        var ops = Operations() with
        {
            VerifyTask = () => { Events.Add("task"); throw new Win32Exception(5); },
            WriteWatch = record =>
            {
                Assert.Contains("watch_task_repair_failed", record.Alerts);
                Events.Add("alert");
                if (alertWriteFails) throw new IOException("Fixture alert is temporarily unavailable");
                AgentUpdateWatchStore.Write(Store.UpdatesRoot, record);
            },
            Act = (state, scm) => LkgWatchHost.Act(Store, Journal.Store, state, scm, Events.Add, work),
        };
        Assert.Equal(0, LkgWatchHost.Run(Watch, ops));
        Assert.Equal(["restart", "verify", "lock", "task", "watch_task_repair_failed", "alert", "rollback"], Events);
        Assert.Equal(!alertWriteFails, AgentUpdateWatchStore.Read(Store.UpdatesRoot)!.Alerts.Contains("watch_task_repair_failed"));
    }

    [Theory]
    [InlineData("launch_requested")]
    [InlineData("install_may_have_started")]
    [InlineData("installing")]
    [InlineData("recovery_required")]
    [InlineData("pending_reboot")]
    [InlineData("health_pending")]
    public void PersistentRestartFailureRecordsOneBoundAlertAndLeavesC2InControl(string phase)
    {
        Journal.Change(j => j with { AttemptId = Attempt, LifecycleGeneration = 4, Phase = phase });
        var log = new LkgHostLog(_root.FullName);
        var ops = Operations() with
        {
            Restart = _ => throw new Win32Exception(193, "fixture raw failure text"),
            Log = log.Write,
            LogRestartWin32 = log.WriteRestartFailure,
            NoInstallerActivity = _ => true,
        };
        Assert.Equal(0, LkgWatchHost.Run(Watch, ops));
        var recorded = Journal.Read();
        Assert.Equal(phase, recorded.Phase);
        Assert.Equal(Attempt, recorded.FailureAttemptId);
        Assert.Equal(Attempt, recorded.AlertAttemptId);
        Assert.Equal(AgentUpdateWatchJournal.RollbackFailed, recorded.FailureCode);
        Assert.Equal(AgentUpdateWatchJournal.RollbackFailed, recorded.AlertCode);
        Assert.Null(recorded.RollbackAttemptId);
        Assert.Equal(0, LkgWatchHost.Run(Watch, ops));
        Assert.Equal(recorded.Revision, Journal.Read().Revision);
        var lines = File.ReadAllLines(Path.Combine(_root.FullName, "logs", "lkg-host.log"));
        Assert.Equal(3, lines.Count(line => line.EndsWith(" watch_restart_failed win32=193", StringComparison.Ordinal)));
        Assert.Single(lines, line => line.EndsWith(" rollback_failed", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, line => line.Contains("fixture raw failure text", StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => log.Write("watch_restart_failed win32=193"));

        if (phase == AgentUpdateStates.RecoveryRequired)
        {
            Assert.True(AgentUpdateLocalService.RecoveryCloseDue(recorded, Now, Now.AddMinutes(-20), false, false));
            var reconciled = Journal.Change(before => AgentUpdateLocalService.CloseRecovery(before, null, false, Now));
            Assert.Equal(AgentUpdateStates.Failed, reconciled.Phase);
            Assert.Equal(AgentUpdateErrorCodes.RecoveryTimeout, reconciled.InstallerResult!.ErrorCode);
            Assert.Null(reconciled.FailureCode);
            Assert.Null(reconciled.RollbackAttemptId);
        }
    }

    [Theory]
    [InlineData("live-runner")]
    [InlineData("live-installer")]
    [InlineData("installer-mutex")]
    [InlineData("in-progress")]
    [InlineData("unreadable")]
    [InlineData("restart-recovers")]
    [InlineData("raced-journal")]
    [InlineData("not-pre-commit")]
    public void RestartFallbackRequiresEachPredicate(string branch)
    {
        Journal.Change(j => j with
        {
            AttemptId = Attempt, Phase = branch == "not-pre-commit" ? AgentUpdateStates.Installed : AgentUpdateStates.Installing,
            RunnerProcessId = 1, RunnerStartedUtc = Now, InstallerProcessId = 2, InstallerStartedUtc = Now,
        });
        var restarts = 0;
        var ops = Operations() with
        {
            Restart = _ =>
            {
                restarts++;
                if (restarts == 2 && branch == "raced-journal")
                    Journal.Change(j => j with { AttemptId = "successor" });
                if (restarts == 2 && branch == "restart-recovers") return;
                throw new Win32Exception(193);
            },
            NoInstallerActivity = active => LkgWatchHostWindows.NoInstallerActivity(active,
                (pid, _) => !(pid == 1 && branch == "live-runner" || pid == 2 && branch == "live-installer"),
                () => branch == "installer-mutex",
                () => branch == "unreadable" ? throw new UnauthorizedAccessException() : branch == "in-progress"),
        };
        Assert.Equal(0, LkgWatchHost.Run(Watch, ops));
        Assert.Equal(branch is "restart-recovers" or "raced-journal" ? 2 : 1, restarts);
        Assert.Null(Journal.Read().FailureCode);
        Assert.Null(Journal.Read().AlertCode);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("timestamp")]
    [InlineData("attempt")]
    [InlineData("watch-attempt")]
    [InlineData("phase")]
    [InlineData("unchanged")]
    public void WatchCloseComparesTheDurableBinding(string change)
    {
        var expected = Journal.Change(j => j with
        {
            AttemptId = Attempt, WatchAttemptId = Attempt, WatchRequestedUtc = Now,
            Phase = AgentUpdateWatchJournal.CommittedWatch, LifecycleGeneration = 3,
        });
        var live = Journal.Change(before => change switch
        {
            "generation" => before with { LifecycleGeneration = 4 },
            "timestamp" => before with { WatchRequestedUtc = Now.AddMinutes(1) },
            "attempt" => before with { AttemptId = "successor" },
            "watch-attempt" => before with { WatchAttemptId = "successor" },
            "phase" => before with { Phase = AgentUpdateStates.Installed },
            _ => before,
        });
        var watch = new AgentUpdateWatchRecord(AgentUpdateWatchRecord.CurrentSchema, Attempt, "1.2.3", 20,
            Guid.NewGuid(), null, null, Now, [], null, 0, 0, null, null, AgentUpdateWatchOutcomes.Inconclusive, []);
        var context = new LkgWatchHostContext(Store, Journal.Store, expected, watch, null, false, false, Events.Add);
        LkgWatchHostBinding.CloseWithoutPromotion(context, watch, AgentUpdateWatchJournal.WatchUnavailable, Journal.Change);
        if (change == "unchanged")
        {
            Assert.Equal(AgentUpdateStates.Installed, Journal.Read().Phase);
            Assert.Equal(Attempt, Journal.Read().WatchOutcomeAttemptId);
            Assert.Equal([AgentUpdateWatchJournal.WatchUnavailable], Events);
        }
        else
        {
            Assert.Equal(live, Journal.Read());
            Assert.Empty(Events);
        }
    }

    private LkgWatchHostOperations Operations() => new(
        () => true, _ => Events.Add("restart"), () => Events.Add("verify"),
        () => LkgWatchHost.ReadSnapshot(Store, Journal.Store),
        () => { Events.Add("lock"); return LkgWatchHost.TryLock(Store); },
        _ => null, _ => throw new Xunit.Sdk.XunitException("Changed an unrelated floor"),
        () => { }, (_, _) => { }, watch => AgentUpdateWatchStore.Write(Store.UpdatesRoot, watch), Events.Add)
    {
        RecordRestartFailure = active => LkgWatchHost.RecordInterruptedRestart(Journal.Change, active),
        ReadUptimeMilliseconds = () => (long)TimeSpan.FromHours(1).TotalMilliseconds,
    };

    public void Dispose() => _root.Delete(recursive: true);
}
