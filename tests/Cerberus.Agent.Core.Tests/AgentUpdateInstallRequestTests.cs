using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Step = Cerberus.Agent.App.Updates.AgentUpdateLocalService.InstallRequestStep;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support-tier checks for the signed install request: accepted modes, start time, scheduler decision and journal field.</summary>
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
    [InlineData("not-a-date", 0)]
    [InlineData("2026-10-27T08:00:00Z", 0)]
    [InlineData("2026-10-27T09:30:00Z", 30 * 60)]
    [InlineData("2026-10-27T12:30:00+03:00", 30 * 60)]
    [InlineData("2026-10-30T09:00:00Z", 24 * 60 * 60)]
    public void NotBefore_IsNeverPastAndAtMostTheRolloutWindowAhead(string? notBefore, int expectedSeconds)
        => Assert.Equal(Now.AddSeconds(expectedSeconds),
            AgentUpdateRequestCommandHandler.InstallNotBefore(notBefore, null, "seed", Now));

    [Fact]
    public void NotBefore_JitterIsDeterministicAndBounded()
    {
        var seeds = Enumerable.Range(0, 200).Select(i => "campaign:idem:" + i).ToArray();
        var offsets = seeds.Select(s => AgentUpdateRequestCommandHandler.InstallNotBefore(null, 600, s, Now) - Now).ToArray();

        Assert.All(offsets, o => Assert.InRange(o, TimeSpan.Zero, TimeSpan.FromSeconds(600)));
        Assert.True(offsets.Distinct().Count() > 1);
        Assert.Equal(offsets[7], AgentUpdateRequestCommandHandler.InstallNotBefore(null, 600, seeds[7], Now) - Now);
        Assert.All(seeds, s => Assert.InRange(AgentUpdateRequestCommandHandler.InstallNotBefore(null, 99999, s, Now) - Now,
            TimeSpan.Zero, TimeSpan.FromSeconds(3600)));
        Assert.Equal(Now, AgentUpdateRequestCommandHandler.InstallNotBefore(null, -5, seeds[0], Now));
    }

    private static AgentUpdateJournal WithRequest(string phase, long generation, DateTimeOffset notBefore, string? attemptId = "attempt-1")
        => new()
        {
            AttemptId = attemptId,
            Phase = phase,
            LifecycleGeneration = 7,
            InstallRequest = new AgentUpdateInstallRequest(notBefore, generation),
        };

    [Theory]
    [InlineData(AgentUpdateStates.Current, 7, 0, (int)Step.Run)]
    [InlineData(AgentUpdateStates.AwaitingConsent, 7, 0, (int)Step.Run)]
    [InlineData(AgentUpdateStates.RetryableBusy, 7, -60, (int)Step.Run)]
    [InlineData(AgentUpdateStates.Current, 7, 60, (int)Step.None)]
    [InlineData(AgentUpdateStates.Current, 6, 0, (int)Step.Drop)]
    [InlineData(AgentUpdateStates.Installing, 6, 0, (int)Step.Drop)]
    [InlineData(AgentUpdateStates.Installing, 7, 0, (int)Step.None)]
    [InlineData(AgentUpdateStates.HealthPending, 7, 0, (int)Step.None)]
    [InlineData("launch_requested", 7, 0, (int)Step.None)]
    public void Scheduler_RunsADueRequestOfThisGenerationOutsideAnInstall(string phase, long generation, int dueInSeconds, int expected)
        => Assert.Equal((Step)expected, AgentUpdateLocalService.NextInstallRequestStep(
            WithRequest(phase, generation, Now.AddSeconds(dueInSeconds)), 7, Now));

    [Fact]
    public void Scheduler_WithoutARequestDoesNothing()
        => Assert.Equal(Step.None, AgentUpdateLocalService.NextInstallRequestStep(new AgentUpdateJournal(), 7, Now));

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
    public void Journal_RequestRoundTrips_NegativeGenerationIsInvalid()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-install-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "transaction.json");
            var store = new AgentUpdateJournalStore(root);
            var request = new AgentUpdateInstallRequest(Now, 7);

            AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { InstallRequest = request });
            Assert.Equal(request, store.Read().InstallRequest);

            AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { InstallRequest = request with { LifecycleGeneration = -1 } });
            Assert.Throws<InvalidOperationException>(() => store.Read());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
