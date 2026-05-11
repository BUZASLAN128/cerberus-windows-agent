using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Tailscale;

namespace Cerberus.Agent.Core.Tests;

public sealed class TailscaleEnsureConnectedHandlerTests
{
    [Fact]
    public async Task HandleAsync_DoesNotWriteUpCommand_WhenDebugExportDisabled()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmp);
        try
        {
            var secretsLoaded = false;
            var handler = new TailscaleEnsureConnectedHandler(
                probe: _ => Task.FromResult((true, false, (object?)new { state = "NeedsLogin" }, (string?)null)),
                secretStoreFactory: () =>
                {
                    secretsLoaded = true;
                    return new StubSecretStore("https://headscale.example", "tskey-auth-123");
                },
                allowUpCommandExport: () => false,
                baseDir: tmp,
                applyAcl: false);

            var result = await handler.HandleAsync(Command(), CancellationToken.None);

            Assert.Equal("FAILED", result.Status);
            Assert.False(secretsLoaded);
            Assert.False(File.Exists(Path.Combine(tmp, "tailscale-up.cmd")));
            Assert.Contains("read-only", result.Stderr);
        }
        finally
        {
            try { Directory.Delete(tmp, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task HandleAsync_WritesUpCommandOnly_WhenDebugExportEnabled()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmp);
        try
        {
            var handler = new TailscaleEnsureConnectedHandler(
                probe: _ => Task.FromResult((true, false, (object?)new { state = "NeedsLogin" }, (string?)null)),
                secretStoreFactory: () => new StubSecretStore("https://headscale.example", "tskey-auth-123"),
                allowUpCommandExport: () => true,
                baseDir: tmp,
                applyAcl: false);

            var result = await handler.HandleAsync(Command(), CancellationToken.None);

            Assert.Equal("DONE", result.Status);
            var cmdPath = Directory.GetFiles(tmp, "tailscale-up-*.cmd").Single();
            var content = await File.ReadAllTextAsync(cmdPath);
            Assert.Contains("tailscale up", content);
            Assert.Contains("tskey-auth-123", content);
            var metadataPath = Directory.GetFiles(tmp, "tailscale-up-*.metadata.json").Single();
            var metadata = await File.ReadAllTextAsync(metadataPath);
            Assert.Contains("cerberus.tailscale-debug-export.v1", metadata);
            Assert.Contains("expires_at_utc", metadata);
        }
        finally
        {
            try { Directory.Delete(tmp, recursive: true); } catch { }
        }
    }

    private static AgentCommand Command()
        => new("cmd-id", "tailscale.ensure_connected", "idem", new { });

    private sealed class StubSecretStore : ISecretStore
    {
        private readonly string? _loginServer;
        private readonly string? _authKey;

        public StubSecretStore(string? loginServer, string? authKey)
        {
            _loginServer = loginServer;
            _authKey = authKey;
        }

        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct)
            => throw new NotSupportedException();

        public Task<(
            AgentIdentity Identity,
            string RefreshToken,
            string PrivateKeyPem,
            string BackendUrl,
            string? TailscaleLoginServer,
            string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((
                new AgentIdentity("agent-1", "tenant-1"),
                "refresh",
                "private",
                "http://backend.test",
                _loginServer,
                _authKey));

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
