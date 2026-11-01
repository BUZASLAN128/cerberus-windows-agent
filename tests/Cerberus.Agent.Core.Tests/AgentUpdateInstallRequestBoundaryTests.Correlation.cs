using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentUpdateInstallRequestBoundaryTests
{
    private static readonly AgentUpdateExpectedPlan Release = new("2.0.0", "stable:42", new string('a', 64));
    private const string Attempt = "11111111111111111111111111111111";

    [Fact]
    public Task PendingStateRejectsAdmissionAndPausesScheduledWork() => WithCorrelationJournal(async root =>
    {
        var journal = new AgentUpdateJournalStore(root);
        var lifecycle = new AgentLifecycleSnapshot { Generation = 7 };
        var initial = FixtureWriter(root)(_ => new() { AttemptId = Attempt, LifecycleGeneration = 7,
            Phase = AgentUpdateStates.AwaitingConsent, Required = true, RequiredPolicyGeneration = 7,
            ApplyNotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(-1) });
        var admissionWrites = 0;
        AgentUpdateJournal Change(Func<AgentUpdateJournal, AgentUpdateJournal> change)
        {
            admissionWrites++;
            return FixtureWriter(root)(change);
        }
        Assert.False(await AgentUpdateLocalService.RequestInstallAsync(DateTimeOffset.UtcNow,
            _ => Task.FromResult(lifecycle), Change, () => false, _ => true, default,
            "pending-command", "campaign", "idem", Release));
        Assert.Equal(0, admissionWrites);
        var work = 0;
        await AgentUpdateLocalService.RunScheduledTickAsync(journal, lifecycle, () => false, _ => true,
            _ => { work++; return Task.FromResult(true); }, _ => { work++; return Task.CompletedTask; },
            () => { work++; return Task.CompletedTask; }, default);
        Assert.Equal(0, work);
        Assert.Equal(initial, journal.Read());
        var due = new AgentUpdateJournal { LifecycleGeneration = 7, InstallRequest = CorrelatedRequest() };
        FixtureWriter(root)(_ => due);
        Assert.True(await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(due, lifecycle, () => false, _ => true,
            FixtureWriter(root), _ => { work++; return Task.FromResult(true); }, NullAgentLogger.Instance, default));
        Assert.Equal(0, work);
        Assert.Equal(due, journal.Read());
        Assert.True(await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(journal.Read(), lifecycle, () => false, _ => false,
            FixtureWriter(root), _ =>
            {
                work++;
                FixtureWriter(root)(before => before with { Phase = AgentUpdateStates.Current,
                    InstallRequest = before.InstallRequest! with { VerifiedRelease = Release } });
                return Task.FromResult(false);
            }, NullAgentLogger.Instance, default));
        Assert.Equal(1, work);
        Assert.Equal("current", journal.Read().InstallRequest!.TerminalReason);
    });

    [Fact]
    public Task DuplicateAfterRestartPreservesRequestIdentityBudgetAndExpiry() => WithCorrelationJournal(async root =>
    {
        var due = DateTimeOffset.UtcNow;
        Task<bool> Request(DateTimeOffset at, string campaign = "campaign", string idem = "idem", AgentUpdateExpectedPlan? plan = null)
            => AgentUpdateLocalService.RequestInstallAsync(at,
                _ => Task.FromResult(new AgentLifecycleSnapshot { Generation = 7 }), FixtureWriter(root), () => false, _ => false,
                default, "command", campaign, idem, plan ?? Release);
        Assert.True(await Request(due));
        FixtureWriter(root)(before => before with { InstallRequest = before.InstallRequest! with
            { Attempts = 2, NotBeforeUtc = due.AddMinutes(5) } });
        var saved = new AgentUpdateJournalStore(root).Read().InstallRequest!;
        Assert.True(await Request(due.AddHours(3)));
        Assert.Equal(saved, new AgentUpdateJournalStore(root).Read().InstallRequest);
        Assert.False(await Request(due, campaign: "different"));
        Assert.False(await Request(due, idem: "different"));
        Assert.False(await Request(due, plan: Release with { ReleaseId = "stable:43" }));
        Assert.Equal(saved, new AgentUpdateJournalStore(root).Read().InstallRequest);
    });

    [Fact]
    public Task ExhaustedRequestRemainsTerminalAfterRestartAndRedelivery() => WithCorrelationJournal(async root =>
    {
        var request = CorrelatedRequest() with { Attempts = 2 };
        FixtureWriter(root)(_ => new() { InstallRequest = request });
        var calls = 0;
        Task<bool> Fail(bool _) { calls++; throw new IOException("fixture staging failure"); }
        await Assert.ThrowsAsync<IOException>(() => AgentUpdateLocalService.RunInstallRequestAsync(
            new AgentUpdateJournalStore(root).Read(), 7, true, FixtureWriter(root), Fail, NullAgentLogger.Instance, default));
        var terminal = new AgentUpdateJournalStore(root).Read().InstallRequest!;
        Assert.Equal(("staging_failed", 3), (terminal.TerminalReason, terminal.Attempts));
        Assert.NotNull(terminal.TerminalUtc);
        Assert.True(await AgentUpdateLocalService.RequestInstallAsync(DateTimeOffset.UtcNow,
            _ => Task.FromResult(new AgentLifecycleSnapshot { Generation = 7 }), FixtureWriter(root), () => false, _ => false,
            default, request.CommandId, request.CampaignId, request.IdempotencyKey, request.ExpectedPlan));
        Assert.False(await AgentUpdateLocalService.RunInstallRequestAsync(new AgentUpdateJournalStore(root).Read(),
            7, true, FixtureWriter(root), Fail, NullAgentLogger.Instance, default));
        Assert.Equal(terminal, new AgentUpdateJournalStore(root).Read().InstallRequest);
        Assert.Equal(1, calls);
    });

    [Theory]
    [InlineData("expired")]
    [InlineData("lifecycle_changed")]
    [InlineData("automatic_updates_disabled")]
    public Task QuarantineDoesNotPreventFiniteRequestTermination(string reason) => WithCorrelationJournal(async root =>
    {
        var request = CorrelatedRequest();
        if (reason == "expired") request = request with { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) };
        if (reason == "lifecycle_changed") request = request with { LifecycleGeneration = 6 };
        var lifecycle = new AgentLifecycleSnapshot { Generation = 7,
            State = reason == "automatic_updates_disabled" ? AgentLifecycleState.NeedsReenrollment : AgentLifecycleState.Active };
        FixtureWriter(root)(_ => new() { InstallRequest = request });
        Task<bool> NoStage(bool _) => throw new InvalidOperationException("A terminal request must not stage.");
        Assert.True(await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(new AgentUpdateJournalStore(root).Read(),
            lifecycle, () => true, _ => false, FixtureWriter(root), NoStage, NullAgentLogger.Instance, default));
        var ended = new AgentUpdateJournalStore(root).Read().InstallRequest!;
        Assert.Equal(reason, ended.TerminalReason);
        Assert.NotNull(ended.TerminalUtc);
        await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(new AgentUpdateJournalStore(root).Read(),
            lifecycle, () => true, _ => false, FixtureWriter(root), NoStage, NullAgentLogger.Instance, default);
        Assert.Equal(ended, new AgentUpdateJournalStore(root).Read().InstallRequest);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task VerifiedCurrentAndSelectedAttemptKeepExactHeartbeatTupleAcrossRestart(bool staged) => WithCorrelationJournal(async root =>
    {
        var request = CorrelatedRequest();
        var plan = Plan();
        FixtureWriter(root)(_ => new() { InstallRequest = request, LifecycleGeneration = 7 });
        Task<bool> Stage(bool _)
        {
            FixtureWriter(root)(before => before with { AttemptId = staged ? Attempt : null,
                Phase = staged ? AgentUpdateStates.AwaitingConsent : AgentUpdateStates.Current,
                InstallRequest = before.InstallRequest! with { VerifiedRelease = Release } });
            return Task.FromResult(staged);
        }
        Assert.True(await AgentUpdateLocalService.RunInstallRequestAsync(new AgentUpdateJournalStore(root).Read(),
            7, true, FixtureWriter(root), Stage, NullAgentLogger.Instance, default));
        var active = new AgentUpdateJournalStore(root).Read();
        if (staged)
        {
            Assert.Equal(Attempt, active.InstallRequest!.BoundAttemptId);
            active = AgentUpdateLocalService.CompleteInstallRequest(active with { Phase = AgentUpdateStates.Installed }, plan, DateTimeOffset.UtcNow);
            FixtureWriter(root)(_ => active);
            active = new AgentUpdateJournalStore(root).Read();
        }
        var projected = AgentUpdateLocalService.ProjectInstallRequest(active, staged ? plan : null,
            AgentUpdateState.NotChecked("2.0.0") with { State = active.Phase });
        var wire = projected.ToHeartbeatStatus();
        Assert.Equal(staged ? "installed" : "current", wire["state"]);
        Assert.Equal(request.CommandId, wire["command_id"]);
        Assert.Equal(request.CampaignId, wire["campaign_id"]);
        Assert.Equal(Release.Version, wire["target_version"]);
        Assert.Equal(Release.ReleaseId, wire["release_id"]);
        Assert.Equal(Release.ArtifactSha256, wire["artifact_sha256"]);
        Assert.Equal(staged ? "installed" : "current", active.InstallRequest!.TerminalReason);
        Assert.Equal(active, AgentUpdateLocalService.CompleteInstallRequest(active, staged ? plan : null, DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal("agent.update.status.v2", wire["schema_version"]);
        Assert.DoesNotContain("terminal_reason", wire.Keys);
        Assert.DoesNotContain("install_request", wire.Keys);
    });

    [Fact]
    public Task MissingTrustedReleaseCannotReportCurrentOrPromoteAnAttempt() => WithCorrelationJournal(async root =>
    {
        FixtureWriter(root)(_ => new() { InstallRequest = CorrelatedRequest() });
        await AgentUpdateLocalService.RunInstallRequestAsync(new AgentUpdateJournalStore(root).Read(),
            7, true, FixtureWriter(root), _ => Task.FromResult(false), NullAgentLogger.Instance, default);
        Assert.Equal("release_unavailable", new AgentUpdateJournalStore(root).Read().InstallRequest!.TerminalReason);
    });

    [Fact]
    public void PendingRequestDoesNotInheritAnUnrelatedInstalledTuple()
    {
        var previous = AgentUpdateState.NotChecked("1.0.0") with { State = AgentUpdateStates.Installed,
            TargetVersion = "old", ArtifactSha256 = new string('b', 64), ReleaseId = "stable:9", AttemptId = Attempt,
            CampaignId = "old-campaign", CommandId = "old-command" };
        var state = AgentUpdateLocalService.ProjectInstallRequest(new() { InstallRequest = CorrelatedRequest() }, null, previous);
        Assert.Equal(AgentUpdateStates.Checking, state.State);
        Assert.Equal("command", state.CommandId);
        Assert.Equal("campaign", state.CampaignId);
        Assert.Equal(Release.Version, state.TargetVersion);
        Assert.Null(state.ArtifactSha256);
        Assert.Null(state.ReleaseId);
        Assert.Null(state.AttemptId);
        var other = previous.Transition(AgentUpdateStates.Checking, commandId: "another-command");
        Assert.Null(other.CampaignId);
        Assert.Null(other.ReleaseId);
        Assert.Null(other.ArtifactSha256);
        Assert.Null(other.TargetVersion);
        Assert.Null(other.AttemptId);
    }

    [Fact]
    public void BoundAttemptHasFiniteDeadlineWithoutChangingItsInstallJournal()
    {
        var request = CorrelatedRequest() with { BoundAttemptId = Attempt, VerifiedRelease = Release,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) };
        var active = new AgentUpdateJournal { InstallRequest = request, AttemptId = Attempt,
            LifecycleGeneration = 7, Phase = AgentUpdateStates.RetryableBusy };
        var completed = AgentUpdateLocalService.CompleteInstallRequest(active, Plan(), DateTimeOffset.UtcNow);
        Assert.Equal("expired", completed.InstallRequest!.TerminalReason);
        Assert.Equal(active.Phase, completed.Phase);
        Assert.Equal(active.AttemptId, completed.AttemptId);
    }

    [Fact]
    public void CompletedRequestCannotLabelASuccessorAttemptAsAlreadyInstalled()
    {
        var request = CorrelatedRequest() with { BoundAttemptId = Attempt, VerifiedRelease = Release,
            TerminalReason = "installed", TerminalUtc = DateTimeOffset.UtcNow };
        var successor = Plan() with { AttemptId = "22222222222222222222222222222222", Version = "3.0.0", Sequence = 43 };
        var active = new AgentUpdateJournal { InstallRequest = request, AttemptId = successor.AttemptId,
            LifecycleGeneration = 7, Phase = AgentUpdateStates.Downloading };
        var projected = AgentUpdateLocalService.ProjectInstallRequest(active, successor,
            AgentUpdateState.NotChecked("2.0.0") with { State = active.Phase, TargetVersion = successor.Version });
        Assert.Equal(AgentUpdateStates.Downloading, projected.State);
        Assert.Equal("3.0.0", projected.TargetVersion);
        Assert.Null(projected.CommandId);
        Assert.Null(projected.CampaignId);
        Assert.Equal(request, active.InstallRequest);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BoundRequestWaitsForActualFinalPhaseAndExpiredReceiptCanRecover(bool pendingReboot)
    {
        var now = DateTimeOffset.UtcNow;
        var request = CorrelatedRequest() with { BoundAttemptId = Attempt, VerifiedRelease = Release,
            ExpiresUtc = pendingReboot ? now.AddMinutes(-1) : now.AddHours(1) };
        var active = new AgentUpdateJournal { AttemptId = Attempt, LifecycleGeneration = 7, InstallRequest = request,
            Phase = pendingReboot ? AgentUpdateStates.PendingReboot : AgentUpdateStates.AwaitingConsent };
        if (!pendingReboot) active = AgentUpdateLocalService.TransitionReconciliationDeferred(active, now.AddMinutes(5));
        Assert.Equal(active, AgentUpdateLocalService.CompleteInstallRequest(active, Plan(), now));
        if (!pendingReboot) active = AgentUpdateLocalService.RestoreReconciliationSnapshot(active, 7);
        else active = active with { InstallRequest = request with { TerminalReason = "expired", TerminalUtc = now } };
        foreach (var phase in new[] { AgentUpdateStates.Installed, AgentUpdateStates.Failed })
        {
            var completed = AgentUpdateLocalService.CompleteInstallRequest(active with { Phase = phase }, Plan(), now);
            Assert.Equal(phase == AgentUpdateStates.Installed ? "installed" : "attempt_failed", completed.InstallRequest!.TerminalReason);
            var projected = AgentUpdateLocalService.ProjectInstallRequest(completed, Plan(), AgentUpdateState.NotChecked() with { State = phase });
            Assert.Equal(phase, projected.State);
            Assert.Equal("command", projected.CommandId);
        }
    }

    [Theory]
    [InlineData("staging_failed", "downloading")]
    [InlineData("current", "failed")]
    public void TerminalOverlayEndsWhenItsJournalPhaseOrAttemptAdvances(string reason, string laterPhase)
    {
        var request = CorrelatedRequest() with { TerminalReason = reason, TerminalUtc = DateTimeOffset.UtcNow,
            VerifiedRelease = reason == "current" ? Release : null, TerminalJournalPhase = AgentUpdateStates.Current };
        var active = new AgentUpdateJournal { InstallRequest = request, Phase = laterPhase,
            AttemptId = reason == "staging_failed" ? "attempt-B" : null };
        var projected = AgentUpdateLocalService.ProjectInstallRequest(active, null, AgentUpdateState.NotChecked() with { State = laterPhase });
        Assert.Equal(laterPhase, projected.State);
        Assert.Null(projected.CommandId);
        Assert.Equal(request, active.InstallRequest);
    }

    [Theory]
    [InlineData(AgentUpdateStates.AwaitingConsent)]
    [InlineData(AgentUpdateStates.RetryableBusy)]
    public Task RealSchedulerTickPlanMismatchPreservesExistingAttemptPolicyAndRetry(string phase)
        => WithCorrelationJournal(async root =>
        {
            var journal = new AgentUpdateJournalStore(root);
            var original = journal.Change(_ => new() { Phase = phase, AttemptId = Attempt, LifecycleGeneration = 7,
                Required = true, RequiredPolicyGeneration = 7, ApplyNotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
                RetryCount = 1, NextRetryUtc = DateTimeOffset.UtcNow.AddSeconds(-1),
                InstallRequest = CorrelatedRequest() with { ExpectedPlan = Release with { ReleaseId = "stable:43" } } });
            var reports = 0;
            var ticks = 0;
            await AgentUpdateLocalService.RunScheduledAsync(default, _ => ValueTask.FromResult(ticks++ == 0),
                ct => AgentUpdateLocalService.RunScheduledTickAsync(journal, new() { Generation = 7 }, () => false, _ => false,
                    _ => { AgentUpdateLocalService.RequireExpectedRelease(journal.Read().InstallRequest, Release); return Task.FromResult(true); },
                    _ => throw new InvalidOperationException("No installer call expected."), () => Task.CompletedTask, ct),
                error => { reports++; return AgentUpdateLocalService.ReportFailureAsync(journal, () => Task.CompletedTask, error); });
            var after = journal.Read();
            Assert.Equal("plan_mismatch", after.InstallRequest!.TerminalReason);
            Assert.Equal(0, reports);
            Assert.Equal((original.AttemptId, original.Phase, original.RequiredPolicyGeneration, original.ApplyNotBeforeUtc,
                original.RetryCount, original.NextRetryUtc), (after.AttemptId, after.Phase, after.RequiredPolicyGeneration,
                after.ApplyNotBeforeUtc, after.RetryCount, after.NextRetryUtc));
        }, protectedJournal: true);

    [Fact]
    public Task RealSchedulerTickDoesNotLaunchExpiredBoundRequestAfterQuarantine() => WithCorrelationJournal(async root =>
    {
        var journal = new AgentUpdateJournalStore(root);
        journal.Change(_ => new() { AttemptId = Attempt, Phase = AgentUpdateStates.AwaitingConsent, LifecycleGeneration = 7,
            Required = true, RequiredInstallAttemptId = Attempt, ApplyNotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
            InstallRequest = CorrelatedRequest() with { BoundAttemptId = Attempt, VerifiedRelease = Release } });
        var tick = 0;
        var launches = 0;
        await AgentUpdateLocalService.RunScheduledAsync(default, _ => ValueTask.FromResult(++tick <= 3), async ct =>
        {
            if (tick == 2) journal.Change(before => before with { InstallRequest = before.InstallRequest! with
                { ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(-1) } });
            journal.Change(before => AgentUpdateLocalService.CompleteInstallRequest(before, Plan(), DateTimeOffset.UtcNow));
            await AgentUpdateLocalService.RunScheduledTickAsync(journal, new() { Generation = 7 }, () => tick < 3, _ => false,
                _ => throw new InvalidOperationException("No new stage expected."),
                _ => { launches++; return Task.CompletedTask; }, () => Task.CompletedTask, ct);
        }, _ => throw new InvalidOperationException("Expiration is a hold, not an installation failure."));
        Assert.Equal(0, launches);
        var ended = journal.Read();
        Assert.Equal("expired", ended.InstallRequest!.TerminalReason);
        Assert.Equal(AgentUpdateStates.AwaitingConsent, ended.Phase);
        Assert.False(ended.Required);
        Assert.Null(ended.RequiredInstallAttemptId);
        Assert.ThrowsAny<OperationCanceledException>(() => AgentUpdateLocalService.HoldExpiredInstallRequest(ended, true, default));
        AgentUpdateLocalService.HoldExpiredInstallRequest(ended, false, default);
    }, protectedJournal: true);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task RealSchedulerTickStillReportsStageAndInstallerFailures(bool installer) => WithCorrelationJournal(async root =>
    {
        var journal = new AgentUpdateJournalStore(root);
        journal.Change(_ => new() { AttemptId = Attempt, Phase = AgentUpdateStates.AwaitingConsent, LifecycleGeneration = 7,
            Required = true, RequiredPolicyGeneration = installer ? 7 : null, ApplyNotBeforeUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
            InstallRequest = installer ? null : CorrelatedRequest() });
        var reports = 0;
        var ticks = 0;
        await AgentUpdateLocalService.RunScheduledAsync(default, _ => ValueTask.FromResult(ticks++ == 0),
            ct => AgentUpdateLocalService.RunScheduledTickAsync(journal, new() { Generation = 7 }, () => false, _ => false,
                _ => throw new IOException("fixture stage I/O"), _ => throw new IOException("fixture installer I/O"),
                () => Task.CompletedTask, ct),
            error => { reports++; return AgentUpdateLocalService.ReportFailureAsync(journal, () => Task.CompletedTask, error); });
        Assert.Equal(1, reports);
        Assert.Equal(AgentUpdateStates.Failed, journal.Read().Phase);
    }, protectedJournal: true);

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public Task RealSchedulerTickReplacementCannotInheritExpiredRequestAuthority(bool mismatch, bool independentPolicy)
        => WithCorrelationJournal(async root =>
        {
            var journal = new AgentUpdateJournalStore(root);
            var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            journal.Change(_ => new() { AttemptId = Attempt, Phase = AgentUpdateStates.AwaitingConsent, LifecycleGeneration = 7,
                Required = true, RequiredInstallAttemptId = Attempt, RequiredPolicyGeneration = independentPolicy ? 7 : null,
                ApplyNotBeforeUtc = expiredAt, InstallRequest = CorrelatedRequest() with { BoundAttemptId = Attempt,
                    VerifiedRelease = Release, ExpiresUtc = expiredAt, TerminalReason = "expired", TerminalUtc = expiredAt } });
            Assert.True(await AgentUpdateLocalService.RequestInstallAsync(mismatch ? DateTimeOffset.UtcNow : DateTimeOffset.UtcNow.AddHours(1),
                _ => Task.FromResult(new AgentLifecycleSnapshot { Generation = 7 }), journal.Change, () => false, _ => false, default,
                "replacement", "campaign", "replacement-idem", mismatch ? Release with { ReleaseId = "stable:43" } : Release));
            var ticks = 0;
            var launches = 0;
            await AgentUpdateLocalService.RunScheduledAsync(default, _ => ValueTask.FromResult(ticks++ == 0),
                ct => AgentUpdateLocalService.RunScheduledTickAsync(journal, new() { Generation = 7 }, () => false, _ => false,
                    _ => { AgentUpdateLocalService.RequireExpectedRelease(journal.Read().InstallRequest, Release); return Task.FromResult(true); },
                    _ => { launches++; return Task.CompletedTask; }, () => Task.CompletedTask, ct),
                _ => throw new InvalidOperationException("Expired authority and plan mismatch are not installer failures."));
            var after = journal.Read();
            Assert.Equal(independentPolicy ? 1 : 0, launches);
            Assert.Equal(independentPolicy, after.Required);
            Assert.Null(after.RequiredInstallAttemptId);
            Assert.Equal(independentPolicy ? 7L : (long?)null, after.RequiredPolicyGeneration);
            Assert.Equal(expiredAt, after.InstallRequestAuthorityExpiresUtc);
            Assert.Equal("replacement", after.InstallRequest!.CommandId);
            Assert.Equal(mismatch ? "plan_mismatch" : null, after.InstallRequest.TerminalReason);
            Assert.Equal((Attempt, AgentUpdateStates.AwaitingConsent), (after.AttemptId, after.Phase));
        }, protectedJournal: true);

    // Unit/support admission + launch guard: this does not execute the protected scheduler journal writer.
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public Task ReplacementAdmissionRevokesExpiredAuthorityAndPreservesIndependentPolicy(bool mismatch, bool independentPolicy)
        => WithCorrelationJournal(async root =>
        {
            var journal = new AgentUpdateJournalStore(root);
            var expiredAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            var seed = new AgentUpdateJournal { AttemptId = Attempt, Phase = AgentUpdateStates.RetryableBusy, LifecycleGeneration = 7,
                Required = true, RequiredInstallAttemptId = Attempt, RequiredPolicyGeneration = independentPolicy ? 7 : null,
                RetryCount = 1, ApplyNotBeforeUtc = expiredAt, NextRetryUtc = expiredAt,
                InstallRequest = CorrelatedRequest() with { BoundAttemptId = Attempt, VerifiedRelease = Release,
                    ExpiresUtc = expiredAt, TerminalReason = "expired", TerminalUtc = expiredAt } };
            FixtureWriter(root)(_ => seed);
            Assert.True(await AgentUpdateLocalService.RequestInstallAsync(mismatch ? DateTimeOffset.UtcNow : DateTimeOffset.UtcNow.AddHours(1),
                _ => Task.FromResult(new AgentLifecycleSnapshot { Generation = 7 }), FixtureWriter(root), () => false, _ => false, default,
                "replacement", "campaign", "replacement-idem", mismatch ? Release with { ReleaseId = "stable:43" } : Release));
            var after = journal.Read();
            Assert.Equal(independentPolicy, after.Required);
            Assert.Null(after.RequiredInstallAttemptId);
            Assert.Equal(expiredAt, after.InstallRequestAuthorityExpiresUtc);
            Assert.Equal((seed.AttemptId, seed.Phase, seed.RequiredPolicyGeneration, seed.ApplyNotBeforeUtc, seed.RetryCount, seed.NextRetryUtc),
                (after.AttemptId, after.Phase, after.RequiredPolicyGeneration, after.ApplyNotBeforeUtc, after.RetryCount, after.NextRetryUtc));
            if (mismatch)
                Assert.Throws<AgentUpdatePlanMismatchException>(() => AgentUpdateLocalService.RequireExpectedRelease(after.InstallRequest, Release));
            if (independentPolicy) AgentUpdateLocalService.HoldExpiredInstallRequest(after, true, default);
            else Assert.ThrowsAny<OperationCanceledException>(() => AgentUpdateLocalService.HoldExpiredInstallRequest(after, true, default));
            AgentUpdateLocalService.HoldExpiredInstallRequest(after, false, default);
        });

    // Real protected journal + projection owner helpers; this does not call CheckAndStageOwnedAsync.
    [Fact]
    public Task RealJournalNewStagePlanMismatchRemainsPublishedAfterRecovery() => WithCorrelationJournal(async root =>
    {
        var journal = new AgentUpdateJournalStore(root);
        var projection = new AgentUpdateStateStore(Path.Combine(root, "state.json"), Path.Combine(root, "result.json"));
        var request = CorrelatedRequest();
        journal.Change(_ => new() { InstallRequest = request, LifecycleGeneration = 7 });
        journal.Change(before => AgentUpdateLocalService.TransitionStageStart(before, true, false, 7, DateTimeOffset.UtcNow.AddDays(1)));
        var publications = 0;
        async Task Project()
        {
            var active = journal.Read();
            Assert.Equal(AgentUpdateStates.Failed, active.Phase);
            Assert.Equal("plan_mismatch", active.InstallRequest!.TerminalReason);
            var state = AgentUpdateLocalService.ProjectInstallRequest(active, null,
                AgentUpdateState.NotChecked("1.0.0") with { State = active.Phase });
            await projection.WriteAsync(state, default);
            publications++;
        }
        await AgentUpdateLocalService.PublishNewStagePlanMismatchAsync(journal, request, Project);
        Assert.Equal(1, publications); // The catch owner publishes before control returns for the rethrow.
        var first = await projection.ReadAsync("1.0.0", default);
        Assert.Equal((AgentUpdateStates.Failed, "install_request_plan_mismatch", request.CommandId),
            (first.State, first.LastErrorCode, first.CommandId));
        var terminal = journal.Read();
        var reconciled = AgentUpdateLocalService.RecoverActiveAttempt(root, terminal, 7, DateTimeOffset.UtcNow, false, null,
            journal.Change, journal.ChangeAttempt, journal.Read);
        Assert.Equal(terminal, reconciled); // Same no-attempt recovery branch used by the next ReconcileOwnedAsync.
        await Project();
        var next = await projection.ReadAsync("1.0.0", default);
        Assert.Equal((first.State, first.LastErrorCode, first.CommandId, first.ReportSequence),
            (next.State, next.LastErrorCode, next.CommandId, next.ReportSequence));
    }, protectedJournal: true);

#if CERBERUS_SERVER_PROFILE
    [Fact]
    public Task ServerOptionalPlanPersistsAndMalformedShapesNeverReachAdmission() => WithCorrelationJournal(async root =>
    {
        var admissions = 0;
        var handler = new AgentUpdateRequestCommandHandler(() => new AgentUpdateCoordinator(null!, NullAgentLogger.Instance),
            new AgentUpdateStateStore(Path.Combine(root, "state.json"), Path.Combine(root, "result.json")),
            NullAgentLogger.Instance, "1.0.0",
            (due, command, campaign, idem, expected, ct) =>
            {
                admissions++;
                return AgentUpdateLocalService.RequestInstallAsync(due,
                    _ => Task.FromResult(new AgentLifecycleSnapshot { Generation = 7 }), FixtureWriter(root), () => false, _ => false,
                    ct, command, campaign, idem, expected);
            }, _ => Task.FromResult(AgentUpdateState.NotChecked("1.0.0")),
            () => new(false, true, "https://updates.example.test/manifest.json", "fixture", "stable"));
        var plan = System.Text.Json.JsonSerializer.Serialize(Release);
        AgentCommand Command(string serialized, string id) => new(id, "agent.update.request", "idem",
            System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(
                "{\"schema_version\":\"agent.update.request.v1\",\"mode\":\"install\",\"plan\":" + serialized + "}"));
        Assert.Equal("DONE", (await handler.HandleAsync(Command(plan, "command"), default)).Status);
        var saved = new AgentUpdateJournalStore(root).Read().InstallRequest;
        Assert.Equal(Release, saved!.ExpectedPlan);
        foreach (var malformed in new[] { plan[..^1] + ",\"extra\":true}",
                     plan[..^1] + ",\"version\":\"2.0.0\"}", "{\"version\":\"2.0.0\"}" })
            Assert.Equal("FAILED", (await handler.HandleAsync(Command(malformed, "other-command"), default)).Status);
        Assert.Equal(1, admissions);
        Assert.Equal(saved, new AgentUpdateJournalStore(root).Read().InstallRequest);
    });
#endif

    private static AgentUpdateInstallRequest CorrelatedRequest() => new(DateTimeOffset.UtcNow.AddMinutes(-1), 7,
        DateTimeOffset.UtcNow.AddHours(24), CommandId: "command", CampaignId: "campaign", IdempotencyKey: "idem", ExpectedPlan: Release);
    private static AgentUpdatePlan Plan() => new("msi", Release.Version, "stable", "fixture.msi", Release.ArtifactSha256,
        DateTimeOffset.UtcNow.ToString("O"), "fixture", AttemptId: Attempt, Sequence: 42);

    private static async Task WithCorrelationJournal(Func<string, Task> assertion, bool protectedJournal = false)
    {
        var prefix = Path.Combine(Path.GetTempPath(), "agent-install-correlation-");
        var root = prefix + Guid.NewGuid().ToString("N");
        if (protectedJournal) AgentUpdateSecurity.EnsureProtectedRoot(root);
        else Directory.CreateDirectory(root);
        try { await assertion(root); }
        finally
        {
            if (!Path.GetFullPath(root).StartsWith(Path.GetFullPath(prefix), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Unexpected fixture cleanup target.");
            Directory.Delete(root, recursive: true);
        }
    }
}
