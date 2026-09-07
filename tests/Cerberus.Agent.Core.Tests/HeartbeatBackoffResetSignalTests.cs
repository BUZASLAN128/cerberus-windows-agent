using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class HeartbeatBackoffResetSignalTests
{
    [Fact]
    public async Task ConsumeAsync_ReturnsTrueOnce_WhenSignalWasRequested()
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "heartbeat-backoff-reset.signal");

        Assert.False(HeartbeatBackoffResetSignal.TryRequest(path, "manual_connect"));
        Assert.False(Directory.Exists(Path.GetDirectoryName(path)));

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        Assert.True(HeartbeatBackoffResetSignal.TryRequest(path, "manual_connect"));

        Assert.True(await HeartbeatBackoffResetSignal.ConsumeAsync(path, CancellationToken.None));
        Assert.False(await HeartbeatBackoffResetSignal.ConsumeAsync(path, CancellationToken.None));
        Directory.Delete(Path.GetDirectoryName(path)!);
    }
}
