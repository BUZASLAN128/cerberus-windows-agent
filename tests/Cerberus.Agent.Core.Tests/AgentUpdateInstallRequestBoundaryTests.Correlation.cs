using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentUpdateInstallRequestBoundaryTests
{
    private static readonly AgentUpdateExpectedPlan Release = new("2.0.0", "stable:42", new string('a', 64));
    private const string Attempt = "11111111111111111111111111111111";

    [Fact]
    public Task DuplicateAfterRestartPreservesRequestIdentityBudgetAndExpiry() => WithCorrelationJournal(async root =>
    {
        var due = DateTimeOffset.UtcNow;
        Task<bool> Request(DateTimeOffset at, string campaign = "campaign", string idem = "idem", AgentUpdateExpectedPlan? plan = null)
            => AgentUpdateLocalService.RequestInstallAsync(at,
                _ => Task.FromResult(new AgentLifecycleSnapshot { Generation = 7 }), FixtureWriter(root), () => false,
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
            _ => Task.FromResult(new AgentLifecycleSnapshot { Generation = 7 }), FixtureWriter(root), () => false,
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
            lifecycle, () => true, FixtureWriter(root), NoStage, NullAgentLogger.Instance, default));
        var ended = new AgentUpdateJournalStore(root).Read().InstallRequest!;
        Assert.Equal(reason, ended.TerminalReason);
        Assert.NotNull(ended.TerminalUtc);
        await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(new AgentUpdateJournalStore(root).Read(),
            lifecycle, () => true, FixtureWriter(root), NoStage, NullAgentLogger.Instance, default);
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
                    _ => Task.FromResult(new AgentLifecycleSnapshot { Generation = 7 }), FixtureWriter(root), () => false,
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

    private static async Task WithCorrelationJournal(Func<string, Task> assertion)
    {
        var prefix = Path.Combine(Path.GetTempPath(), "agent-install-correlation-");
        var root = prefix + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(root);
        try { await assertion(root); }
        finally
        {
            if (!Path.GetFullPath(root).StartsWith(Path.GetFullPath(prefix), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Unexpected fixture cleanup target.");
            Directory.Delete(root, recursive: true);
        }
    }
}
