using System.Text.Json;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Step = Cerberus.Agent.App.Updates.AgentUpdateLocalService.InstallRequestStep;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support-tier checks for the signed install request: accepted modes, start time, scheduler decision, retries and journal field.</summary>
public sealed class AgentUpdateInstallRequestTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-10-27T09:00:00Z");

    [Theory]
    [InlineData("install")]
    [InlineData("check")]
    [InlineData("stage")]
    [InlineData("stage_and_prompt")]
    [InlineData("force_install")]
    [InlineData("")]
    [InlineData(null)]
    public void Modes_ServerOnlyInstalls_DesktopKeepsItsModes(string? mode)
    {
#if CERBERUS_SERVER_PROFILE
        var expected = mode == "install";
#else
        var expected = mode is "check" or "stage" or "stage_and_prompt";
#endif
        Assert.Equal(expected, AgentUpdateRequestCommandHandler.SupportsMode(mode));
    }

    [Theory]
    [InlineData(null, 0)]
    [InlineData("  ", 0)]
    [InlineData("2026-10-27T08:00:00Z", 0)]
    [InlineData("2026-10-27T09:30:00Z", 30 * 60)]
    [InlineData("2026-10-27T09:30:00z", 30 * 60)]
    [InlineData("2026-10-27T12:30:00+03:00", 30 * 60)]
    [InlineData("2026-10-28T09:00:00Z", 24 * 60 * 60)]
    public void NotBefore_IsNeverPastAndAtMostTheRolloutWindowAhead(string? notBefore, int expectedSeconds)
        => Assert.Equal(Now.AddSeconds(expectedSeconds),
            AgentUpdateRequestCommandHandler.InstallNotBefore(notBefore, null, "seed", Now));

    [Theory]
    [InlineData("not-a-date")]
    [InlineData("2026-10-27T09:30:00")]
    [InlineData("2026-10-27")]
    [InlineData("2026-10-30T09:00:00Z")]
    [InlineData("2026-10-28T09:00:01Z")]
    public void NotBefore_WithoutOffsetUnparsableOrBeyondTheWindowIsRejected(string notBefore)
        => Assert.Null(AgentUpdateRequestCommandHandler.InstallNotBefore(notBefore, 600, "seed", Now));

    [Fact]
    public void NotBefore_JitterIsDeterministicAndBounded()
    {
        TimeSpan Offset(int? jitter, string seed, string? notBefore = null)
            => AgentUpdateRequestCommandHandler.InstallNotBefore(notBefore, jitter, seed, Now)!.Value - Now;
        var seeds = Enumerable.Range(0, 200).Select(i => "campaign:idem:" + i).ToArray();
        var offsets = seeds.Select(s => Offset(600, s)).ToArray();

        Assert.All(offsets, o => Assert.InRange(o, TimeSpan.Zero, TimeSpan.FromSeconds(600)));
        Assert.True(offsets.Distinct().Count() > 1);
        Assert.Equal(offsets[7], Offset(600, seeds[7]));
        Assert.All(seeds, s => Assert.InRange(Offset(99999, s), TimeSpan.Zero, TimeSpan.FromSeconds(3600)));
        Assert.Equal(TimeSpan.Zero, Offset(-5, seeds[0]));
        Assert.All(seeds, s => Assert.Equal(TimeSpan.FromHours(24), Offset(3600, s, "2026-10-28T09:00:00Z")));
    }

    private static AgentUpdateJournal WithRequest(string phase, long generation, DateTimeOffset notBefore, DateTimeOffset expires)
        => new()
        {
            AttemptId = "attempt-1",
            Phase = phase,
            LifecycleGeneration = 7,
            InstallRequest = new AgentUpdateInstallRequest(notBefore, generation, expires),
        };

    [Theory]
    [InlineData(AgentUpdateStates.Current, 7, 0, true, 3600, (int)Step.Run)]
    [InlineData(AgentUpdateStates.AwaitingConsent, 7, 0, true, 3600, (int)Step.Run)]
    [InlineData(AgentUpdateStates.RetryableBusy, 7, -60, true, 3600, (int)Step.Run)]
    [InlineData(AgentUpdateStates.Current, 7, 60, true, 3600, (int)Step.None)]
    [InlineData(AgentUpdateStates.Installing, 7, 0, true, 3600, (int)Step.None)]
    [InlineData(AgentUpdateStates.HealthPending, 7, 0, true, 3600, (int)Step.None)]
    [InlineData("launch_requested", 7, 0, true, 3600, (int)Step.None)]
    [InlineData(AgentUpdateStates.Current, 6, 0, true, 3600, (int)Step.Drop)]
    [InlineData(AgentUpdateStates.Installing, 6, 0, true, 3600, (int)Step.Drop)]
    [InlineData(AgentUpdateStates.Current, 7, 0, false, 3600, (int)Step.Drop)]
    [InlineData(AgentUpdateStates.Current, 7, 60, false, 3600, (int)Step.Drop)]
    [InlineData(AgentUpdateStates.Current, 7, -60, true, 0, (int)Step.Drop)]
    [InlineData(AgentUpdateStates.PendingReboot, 7, -60, true, -1, (int)Step.Drop)]
    [InlineData(AgentUpdateStates.Installing, 7, -60, true, -1, (int)Step.Drop)]
    public void Scheduler_RunsADueRequestOfThisGenerationOutsideAnInstall(
        string phase, long generation, int dueInSeconds, bool allowed, int expiresInSeconds, int expected)
        => Assert.Equal((Step)expected, AgentUpdateLocalService.NextInstallRequestStep(
            WithRequest(phase, generation, Now.AddSeconds(dueInSeconds), Now.AddSeconds(expiresInSeconds)), 7, allowed, Now));

    [Fact]
    public void Scheduler_WithoutARequestDoesNothing()
    {
        Assert.Equal(Step.None, AgentUpdateLocalService.NextInstallRequestStep(new AgentUpdateJournal(), 7, true, Now));
        Assert.Equal(Step.None, AgentUpdateLocalService.NextInstallRequestStep(new AgentUpdateJournal(), 7, false, Now));
    }

    [Fact]
    public void Retry_IsDueAfterTheDelayUntilTriesOrTimeRunOut()
    {
        var request = new AgentUpdateInstallRequest(Now, 7, Now.AddHours(24));

        var first = AgentUpdateLocalService.RetryInstallRequest(request, Now);
        Assert.Equal(request with { Attempts = 1, NotBeforeUtc = Now + AgentUpdateLocalService.InstallRequestRetryDelay }, first);
        var second = AgentUpdateLocalService.RetryInstallRequest(first!, Now);
        Assert.Equal(2, second!.Attempts);
        Assert.Null(AgentUpdateLocalService.RetryInstallRequest(second, Now));
        Assert.Equal(AgentUpdateLocalService.MaxInstallRequestAttempts, second.Attempts + 1);

        Assert.Null(AgentUpdateLocalService.RetryInstallRequest(request with { ExpiresUtc = Now.AddMinutes(4) }, Now));
    }

    private sealed class MemoryJournal(AgentUpdateJournal journal)
    {
        public AgentUpdateJournal Value { get; set; } = journal;
        public AgentUpdateJournal Change(Func<AgentUpdateJournal, AgentUpdateJournal> change) => Value = change(Value);
    }

    private static AgentUpdateInstallRequest DueRequest()
        => new(DateTimeOffset.UtcNow.AddSeconds(-1), 7, DateTimeOffset.UtcNow.AddHours(1));

    [Fact]
    public async Task Run_FailedStagingKeepsTheRequestForALaterTryAndRethrows()
    {
        var request = DueRequest();
        var journal = new MemoryJournal(new AgentUpdateJournal { InstallRequest = request });

        await Assert.ThrowsAsync<InvalidOperationException>(() => AgentUpdateLocalService.RunInstallRequestAsync(
            journal.Value, 7, true, journal.Change, () => throw new InvalidOperationException("manifest unavailable"),
            NullAgentLogger.Instance, CancellationToken.None));

        var kept = journal.Value.InstallRequest;
        Assert.NotNull(kept);
        Assert.Equal(1, kept.Attempts);
        Assert.Equal(request.ExpiresUtc, kept.ExpiresUtc);
        Assert.True(kept.NotBeforeUtc > DateTimeOffset.UtcNow.AddMinutes(4));
        Assert.Equal(Step.None, AgentUpdateLocalService.NextInstallRequestStep(journal.Value, 7, true, DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task Run_StagedRequestIsClearedAndTheAttemptMadeDue()
    {
        var journal = new MemoryJournal(new AgentUpdateJournal { InstallRequest = DueRequest() });
        Task Stage()
        {
            journal.Value = journal.Value with
            {
                AttemptId = "attempt-1", Phase = AgentUpdateStates.AwaitingConsent, Required = true,
                LifecycleGeneration = 7, ApplyNotBeforeUtc = DateTimeOffset.UtcNow.AddHours(20),
            };
            return Task.CompletedTask;
        }

        Assert.True(await AgentUpdateLocalService.RunInstallRequestAsync(
            journal.Value, 7, true, journal.Change, Stage, NullAgentLogger.Instance, CancellationToken.None));

        Assert.Null(journal.Value.InstallRequest);
        Assert.True(journal.Value.ApplyNotBeforeUtc <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Run_ARequestRecordedDuringStagingIsKept()
    {
        var journal = new MemoryJournal(new AgentUpdateJournal { InstallRequest = DueRequest() });
        var newer = DueRequest() with { NotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(30) };
        Task Stage()
        {
            journal.Value = journal.Value with { InstallRequest = newer };
            throw new InvalidOperationException("download failed");
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() => AgentUpdateLocalService.RunInstallRequestAsync(
            journal.Value, 7, true, journal.Change, Stage, NullAgentLogger.Instance, CancellationToken.None));
        Assert.Equal(newer, journal.Value.InstallRequest);

        journal.Value = new AgentUpdateJournal { InstallRequest = DueRequest() };
        Assert.True(await AgentUpdateLocalService.RunInstallRequestAsync(journal.Value, 7, true, journal.Change,
            () => { journal.Value = journal.Value with { InstallRequest = newer }; return Task.CompletedTask; },
            NullAgentLogger.Instance, CancellationToken.None));
        Assert.Equal(newer, journal.Value.InstallRequest);
    }

    [Fact]
    public async Task Run_CancellationLeavesTheRequestUntouched()
    {
        var request = DueRequest();
        var journal = new MemoryJournal(new AgentUpdateJournal { InstallRequest = request });
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => AgentUpdateLocalService.RunInstallRequestAsync(
            journal.Value, 7, true, journal.Change, () => throw new OperationCanceledException(cts.Token),
            NullAgentLogger.Instance, cts.Token));
        Assert.Equal(request, journal.Value.InstallRequest);
    }

    [Theory]
    [InlineData(6, true)]
    [InlineData(7, false)]
    public async Task Run_LapsedRequestIsDroppedWithoutStaging(long generation, bool allowed)
    {
        var journal = new MemoryJournal(new AgentUpdateJournal { InstallRequest = DueRequest() with { LifecycleGeneration = generation } });
        var staged = false;

        Assert.False(await AgentUpdateLocalService.RunInstallRequestAsync(journal.Value, 7, allowed, journal.Change,
            () => { staged = true; return Task.CompletedTask; }, NullAgentLogger.Instance, CancellationToken.None));
        Assert.False(staged);
        Assert.Null(journal.Value.InstallRequest);
    }

    private static AgentUpdateJournal Awaiting(bool required, long generation, DateTimeOffset? applyNotBefore, string phase = AgentUpdateStates.AwaitingConsent)
        => new()
        {
            AttemptId = "attempt-1",
            Phase = phase,
            Required = required,
            LifecycleGeneration = generation,
            ApplyNotBeforeUtc = applyNotBefore,
        };

    [Fact]
    public void Requested_MakesARequiredAttemptOfThisGenerationDueNow()
    {
        Assert.Equal(Now, AgentUpdateLocalService.TransitionInstallRequested(Awaiting(true, 7, Now.AddHours(20)), 7, Now).ApplyNotBeforeUtc);
        Assert.Equal(Now, AgentUpdateLocalService.TransitionInstallRequested(Awaiting(true, 7, null), 7, Now).ApplyNotBeforeUtc);
    }

    [Fact]
    public void Requested_LeavesEveryOtherJournalUnchanged()
    {
        var cases = new[]
        {
            Awaiting(true, 7, Now.AddMinutes(-5)),
            Awaiting(false, 7, null),
            Awaiting(true, 6, Now.AddHours(20)),
            Awaiting(true, 7, Now.AddHours(20), AgentUpdateStates.RetryableBusy),
            Awaiting(true, 7, Now.AddHours(20)) with { AttemptId = null },
        };
        Assert.All(cases, journal => Assert.Equal(journal, AgentUpdateLocalService.TransitionInstallRequested(journal, 7, Now)));
    }

    [Fact]
    public void Journal_RequestRoundTrips_NegativeGenerationOrAttemptsAreInvalid()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-install-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "transaction.json");
            var store = new AgentUpdateJournalStore(root);
            var request = new AgentUpdateInstallRequest(Now, 7, Now.AddHours(24), 2);

            AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { InstallRequest = request });
            Assert.Equal(request, store.Read().InstallRequest);

            AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { InstallRequest = request with { LifecycleGeneration = -1 } });
            Assert.Throws<InvalidOperationException>(() => store.Read());
            AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { InstallRequest = request with { Attempts = -1 } });
            Assert.Throws<InvalidOperationException>(() => store.Read());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

#if CERBERUS_SERVER_PROFILE
    [Theory]
    [InlineData("""{"schema_version":"agent.update.request.v0","mode":"install"}""", "Unsupported update request schema.")]
    [InlineData("""{"schema_version":"agent.update.request.v1","mode":"stage"}""", "Unsupported update request mode.")]
    [InlineData("""{"schema_version":"agent.update.request.v1","mode":"install","jitter_seconds":"soon"}""", "Update request payload is invalid.")]
    [InlineData("""{"schema_version":"agent.update.request.v1","mode":"install","not_before_utc":"2026-10-27T09:30:00"}""", AgentUpdateRequestCommandHandler.InvalidNotBefore)]
    [InlineData("""{"schema_version":"agent.update.request.v1","mode":"install"}""", "Update trust is not configured.")]
    public async Task Server_RejectionReturnsFailedAndWritesNoState(string payload, string stderr)
    {
        var state = Path.Combine(Path.GetTempPath(), "cerberus-update-install-" + Guid.NewGuid().ToString("N"));
        var handler = new AgentUpdateRequestCommandHandler(() => null,
            new AgentUpdateStateStore(state + "-state.json", state + "-result.json"), NullAgentLogger.Instance, "1.2.3");

        var result = await handler.HandleAsync(new AgentCommand("cmd-1", "agent.update.request", "idem-1",
            JsonDocument.Parse(payload).RootElement.Clone()), CancellationToken.None);

        Assert.Equal(("FAILED", 1, stderr), (result.Status, result.ExitCode, result.Stderr));
        Assert.False(File.Exists(state + "-state.json"));
    }
#endif
}
