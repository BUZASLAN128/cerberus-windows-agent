using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class DpapiSecretStoreTests
{
    [Fact]
    public async Task SaveAsync_StoresDpapiProtectedPayloadWithoutPlaintextSecrets()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var store = new DpapiSecretStore(SecretStoreScope.User, dir);
        var path = Path.Combine(dir, "secrets.json");
        var identity = new AgentIdentity("agent-secure-id", "tenant-secure-id");

        await store.SaveAsync(
            identity,
            "refresh-token-that-must-not-be-plaintext",
            "private-key-that-must-not-be-plaintext",
            "http://backend.local",
            tailscaleLoginServer: "https://tailnet.local",
            tailscaleAuthkey: "tskey-that-must-not-be-plaintext",
            CancellationToken.None);

        var encrypted = await File.ReadAllBytesAsync(path);
        var decodedAsText = System.Text.Encoding.UTF8.GetString(encrypted);

        Assert.DoesNotContain("refresh-token-that-must-not-be-plaintext", decodedAsText);
        Assert.DoesNotContain("private-key-that-must-not-be-plaintext", decodedAsText);
        Assert.DoesNotContain("tskey-that-must-not-be-plaintext", decodedAsText);

        var loaded = await store.LoadAsync(CancellationToken.None);
        Assert.Equal(identity, loaded.Identity);
        Assert.Equal("refresh-token-that-must-not-be-plaintext", loaded.RefreshToken);
        Assert.Equal("private-key-that-must-not-be-plaintext", loaded.PrivateKeyPem);
        Assert.Equal("tskey-that-must-not-be-plaintext", loaded.TailscaleAuthkey);
    }

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
