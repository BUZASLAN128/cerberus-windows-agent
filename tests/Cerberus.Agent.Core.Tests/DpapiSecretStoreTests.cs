using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class DpapiSecretStoreTests
{
    [Fact]
    public async Task ProductIdentitySurvivesReloadAndOldBinaryCannotReadSecondaryRecord()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-product-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new DpapiSecretStore(SecretStoreScope.User, dir);
            var identity = new AgentIdentity("agent-secondary", "tenant-secondary", AgentProducts.Secondary);
            await store.SaveAsync(identity, "fixture-refresh", "fixture-key", "https://secondary.example", null, null, default);
            var bytes = await File.ReadAllBytesAsync(Path.Combine(dir, "secrets.json"));
            // An older binary always passes the whole file and no entropy to DPAPI.
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
                System.Security.Cryptography.ProtectedData.Unprotect(bytes, null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser));
            var reopened = await new DpapiSecretStore(SecretStoreScope.User, dir).LoadAsync(default);
            Assert.Equal(identity, reopened.Identity);
            Assert.Equal("https://secondary.example", reopened.BackendUrl);
            await store.ClearAsync(default);
        }
        finally
        {
            var file = Path.Combine(dir, "secrets.json");
            if (File.Exists(file)) File.Delete(file);
            if (Directory.Exists(dir)) Directory.Delete(dir);
        }
    }

    [Fact]
    public async Task UnknownProductIsNeverStored()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-product-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new DpapiSecretStore(SecretStoreScope.User, dir);
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.SaveAsync(
                new AgentIdentity("a", "t", "unknown"), "fixture", "fixture", "https://example.test", null, null, default));
            Assert.False(File.Exists(Path.Combine(dir, "secrets.json")));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir);
        }
    }
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
