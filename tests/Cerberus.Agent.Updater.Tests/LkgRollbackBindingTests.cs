using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed class LkgRollbackBindingTests
{
    [Fact]
    public void RollbackReceiptCannotBindToAnotherWatchGenerationOrInstallerAttempt()
    {
        var now = DateTimeOffset.UnixEpoch.AddHours(1);
        var expected = new AgentUpdateJournal
        {
            Phase = AgentUpdateWatchJournal.RollingBack,
            AttemptId = "watched",
            WatchAttemptId = "watched",
            WatchRequestedUtc = now,
            LifecycleGeneration = 2,
            RollbackAttemptId = "rollback",
            RollbackFirstUtc = now,
            RollbackStartedUtc = now,
        };

        Assert.True(LkgRollback.SameAuthority(expected with { InstallerProcessId = 123 }, expected, "watched"));
        Assert.False(LkgRollback.SameAuthority(expected with { WatchAttemptId = "stale" }, expected, "watched"));
        Assert.False(LkgRollback.SameAuthority(expected with { LifecycleGeneration = 3 }, expected, "watched"));
        Assert.False(LkgRollback.SameAuthority(expected with { RollbackAttemptId = "replacement" }, expected, "watched"));
    }
}
