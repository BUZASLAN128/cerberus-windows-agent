namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateBitsProgressWatchTests
{
    [Fact]
    public void NoGrowth15Min_Throws()
    {
        var elapsed = TimeSpan.Zero;
        var watch = new AgentUpdateBitsProgressWatch(() => elapsed);
        watch.Observe(0);

        elapsed = TimeSpan.FromMinutes(15) - TimeSpan.FromTicks(1);
        watch.Observe(0);

        elapsed = TimeSpan.FromMinutes(15);
        var failure = Assert.Throws<InvalidOperationException>(() => watch.Observe(0));
        Assert.Equal("BITS update download failed: no progress.", failure.Message);
        Assert.Equal(AgentUpdateErrorCodes.DownloadFailed, AgentUpdateErrorCodes.Classify(failure));
    }

    [Fact]
    public void GrowthResetsTimer()
    {
        var elapsed = TimeSpan.Zero;
        var watch = new AgentUpdateBitsProgressWatch(() => elapsed);
        watch.Observe(0);

        elapsed = TimeSpan.FromMinutes(14);
        watch.Observe(128);
        elapsed = TimeSpan.FromMinutes(28);
        watch.Observe(128);

        elapsed = TimeSpan.FromMinutes(29);
        Assert.Throws<InvalidOperationException>(() => watch.Observe(128));
    }

    [Fact]
    public void RestoringPreviouslyTransferredBytesDoesNotResetTimer()
    {
        var elapsed = TimeSpan.Zero;
        var watch = new AgentUpdateBitsProgressWatch(() => elapsed);
        watch.Observe(128);

        elapsed = TimeSpan.FromMinutes(8);
        watch.Observe(64);
        elapsed = TimeSpan.FromMinutes(14);
        watch.Observe(128);

        elapsed = TimeSpan.FromMinutes(15);
        Assert.Throws<InvalidOperationException>(() => watch.Observe(128));
    }

    [Fact]
    public void OverallCapDoesNotExtendWithGrowth()
    {
        var elapsed = TimeSpan.Zero;
        var watch = new AgentUpdateBitsProgressWatch(() => elapsed);
        for (var minute = 0; minute < 60; minute += 10)
        {
            elapsed = TimeSpan.FromMinutes(minute);
            watch.Observe((ulong)minute);
        }

        elapsed = TimeSpan.FromHours(1) - TimeSpan.FromTicks(1);
        watch.ThrowIfOverallTimedOut();
        watch.Observe(59);

        elapsed = TimeSpan.FromHours(1);
        var failure = Assert.Throws<InvalidOperationException>(watch.ThrowIfOverallTimedOut);
        Assert.Equal("BITS update download timed out.", failure.Message);
        Assert.Equal(failure.Message, Assert.Throws<InvalidOperationException>(() => watch.Observe(60)).Message);
    }
}
