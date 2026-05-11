using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class DpapiSecretStoreTests
{
    [Fact]
    public async Task ClearAsync_OverwritesAndDeletesSecretFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var store = new DpapiSecretStore(SecretStoreScope.User, dir);
        var path = Path.Combine(dir, "secrets.json");

        await store.SaveAsync(
            new AgentIdentity("agent-id", "tenant-id"),
            "refresh-token",
            "private-key",
            "http://backend.local",
            tailscaleLoginServer: null,
            tailscaleAuthkey: null,
            CancellationToken.None);
        Assert.True(File.Exists(path));

        await store.ClearAsync(CancellationToken.None);

        Assert.False(File.Exists(path));
    }
}
