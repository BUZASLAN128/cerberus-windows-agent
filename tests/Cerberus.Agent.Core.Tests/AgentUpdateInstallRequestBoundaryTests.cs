using System.Text.Json;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support checks only: isolated journal/delegates, no installed service or download.</summary>
public sealed partial class AgentUpdateInstallRequestBoundaryTests
{
    [Fact]
    public Task PendingDeliveryAtStageEntryKeepsRequestBudgetAndRemainsBoundedByExpiry() => WithCorrelationJournal(async root =>
    {
        var journal = new AgentUpdateJournalStore(root);
        var lifecycle = new AgentLifecycleSnapshot { Generation = 7 };
        var original = FixtureWriter(root)(_ => new() { LifecycleGeneration = 7, InstallRequest = CorrelatedRequest() });
        var entered = 0;
        Task<bool> HeldStage(bool _)
        {
            entered++;
            AgentUpdateLocalService.HoldWhileQuarantined(true, default, () => true);
            return Task.FromResult(false);
        }
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AgentUpdateLocalService.HoldOrRunInstallRequestAsync(
            journal.Read(), lifecycle, () => false, _ => false, FixtureWriter(root), HeldStage, NullAgentLogger.Instance, default));
        Assert.Equal(1, entered);
        Assert.Equal(original, journal.Read());
        Assert.Null(journal.Read().InstallRequest!.TerminalReason);
        Assert.Equal(0, journal.Read().InstallRequest!.Attempts);
        var expired = FixtureWriter(root)(before => before with { InstallRequest = before.InstallRequest! with
            { ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(-1) } });
        Assert.True(await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(expired, lifecycle, () => false, _ => true,
            FixtureWriter(root), HeldStage, NullAgentLogger.Instance, default));
        Assert.Equal(1, entered);
        Assert.Equal("expired", journal.Read().InstallRequest!.TerminalReason);
    });

    [Fact]
    public async Task SignedQuarantineHoldsEntireSchedulerAndAutomaticLaunchUntilReleased()
    {
        var quarantined = true;
        Func<bool> gate = () => AgentUpdateLocalService.Quarantined(() => quarantined, isServer: true);
        Assert.True(AgentUpdateLocalService.Quarantined(null, isServer: true));
        Assert.True(AgentUpdateLocalService.Quarantined(() => throw new IOException(), isServer: true));
        Assert.False(AgentUpdateLocalService.Quarantined(() => true, isServer: false));
        var now = DateTimeOffset.UtcNow;
        var request = new AgentUpdateInstallRequest(now.AddMinutes(-1), 7, now.AddHours(24));
        var active = new AgentUpdateJournal { InstallRequest = request };
        var lifecycle = new AgentLifecycleSnapshot { Generation = 7 };
        var staged = 0;
        var changes = 0;
        AgentUpdateJournal Change(Func<AgentUpdateJournal, AgentUpdateJournal> update)
        {
            changes++;
            return active = update(active);
        }
        Task<bool> Stage(bool required) { Assert.False(required); staged++; return Task.FromResult(true); }

        // A true result ends the whole scheduler tick, including when no request exists.
        Assert.True(await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(new AgentUpdateJournal(), lifecycle,
            gate, _ => false, Change, Stage, NullAgentLogger.Instance, default));
        Assert.True(await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(active, lifecycle,
            gate, _ => false, Change, Stage, NullAgentLogger.Instance, default));
        Assert.Equal(0, staged);
        Assert.Equal(0, changes);
        Assert.Equal(request, active.InstallRequest);
        Assert.ThrowsAny<OperationCanceledException>(() => AgentUpdateLocalService.HoldWhileQuarantined(true, default, gate));
        if (AgentBuildProfile.IsServer)
            Assert.ThrowsAny<OperationCanceledException>(() => AgentUpdateLocalService.HoldWhileQuarantined(false, default, gate));
        else AgentUpdateLocalService.HoldWhileQuarantined(false, default, gate);

        quarantined = false;
        AgentUpdateLocalService.HoldWhileQuarantined(true, default, gate);
        Assert.True(await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(active, lifecycle,
            gate, _ => false, Change, Stage, NullAgentLogger.Instance, default));
        Assert.Equal(1, staged);
        Assert.Null(active.InstallRequest);
        active = active with { InstallRequest = request with { LifecycleGeneration = 6 } };
        Assert.False(await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(active, lifecycle,
            gate, _ => false, Change, Stage, NullAgentLogger.Instance, default));
        Assert.Equal(1, staged);
        Assert.Null(active.InstallRequest);
    }

    [Fact]
    public async Task AcceptedRequestPersistsCurrentGenerationWithoutStartingWork()
    {
        var root = Path.Combine(Path.GetTempPath(), "agent-install-request-boundary-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var journal = new AgentUpdateJournalStore(root);
            var due = DateTimeOffset.UtcNow.AddHours(2);
            Assert.True(await AgentUpdateLocalService.RequestInstallAsync(due,
                _ => Task.FromResult(new AgentLifecycleSnapshot { Generation = 17 }), FixtureWriter(root), () => false, _ => false, default));
            var persisted = new AgentUpdateJournalStore(root).Read();
            Assert.Equal(new AgentUpdateInstallRequest(due, 17, due.AddHours(24)), persisted.InstallRequest);
            Assert.Null(persisted.AttemptId);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

#if CERBERUS_SERVER_PROFILE
    [Fact]
    public async Task ServerInstallHandlerReturnsDoneForFutureRequestAndFailedForForbiddenState()
    {
        var root = Path.Combine(Path.GetTempPath(), "agent-install-handler-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var journal = new AgentUpdateJournalStore(root);
            var lifecycle = new AgentLifecycleSnapshot { Generation = 23 };
            var quarantined = false;
            var projected = AgentUpdateState.NotChecked("1.2.3");
            var handler = new AgentUpdateRequestCommandHandler(() => new AgentUpdateCoordinator(null!, NullAgentLogger.Instance),
                new AgentUpdateStateStore(Path.Combine(root, "state.json"), Path.Combine(root, "result.json")),
                NullAgentLogger.Instance, "1.2.3",
                (due, commandId, campaignId, idempotencyKey, expectedPlan, ct) => AgentUpdateLocalService.RequestInstallAsync(due, _ => Task.FromResult(lifecycle),
                    FixtureWriter(root), () => quarantined, _ => false, ct, commandId, campaignId, idempotencyKey, expectedPlan),
                _ => Task.FromResult(projected),
                () => new AgentUpdateSignal(false, true, "https://updates.example.test/manifest.json", "test", "stable"));
            var due = DateTimeOffset.UtcNow.AddHours(12);
            var command = new AgentCommand("install-1", "agent.update.request", "idem-1",
                JsonSerializer.SerializeToElement(new { schema_version = "agent.update.request.v1", mode = "install", not_before_utc = due.ToString("O") }));

            // The future start cannot be awaited: this must finish without any staging task or clock advance.
            var accepted = await handler.HandleAsync(command, default).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(("DONE", 0), (accepted.Status, accepted.ExitCode));
            var persisted = new AgentUpdateJournalStore(root).Read();
            Assert.Equal(new AgentUpdateInstallRequest(due, 23, due.AddHours(24), CommandId: command.Id, CampaignId: command.Id, IdempotencyKey: command.IdempotencyKey), persisted.InstallRequest);
            Assert.Null(persisted.AttemptId);

            lifecycle = lifecycle with { State = AgentLifecycleState.NeedsReenrollment, Generation = 24 };
            var forbidden = await handler.HandleAsync(command with { Id = "install-2" }, default);
            Assert.Equal(("FAILED", 1), (forbidden.Status, forbidden.ExitCode));
            Assert.Equal(persisted, journal.Read());
            lifecycle = lifecycle with { State = AgentLifecycleState.Active };
            quarantined = true;
            Assert.Equal("FAILED", (await handler.HandleAsync(command with { Id = "install-3" }, default)).Status);
            Assert.Equal(persisted, journal.Read());
        }
        finally { Directory.Delete(root, recursive: true); }
    }
#endif

    // Support fixture: the production SYSTEM-only lock remains in Journal.Change.
    // This writes only the task's temporary journal through the existing durable-file codec.
    private static Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> FixtureWriter(string root)
        => update =>
        {
            var next = update(new AgentUpdateJournalStore(root).Read());
            AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, next);
            return next;
        };
}
