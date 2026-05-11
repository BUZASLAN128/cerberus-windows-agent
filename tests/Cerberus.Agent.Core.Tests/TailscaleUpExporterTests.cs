using Cerberus.Agent.App;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Tailscale;

namespace Cerberus.Agent.Core.Tests;

public sealed class TailscaleUpExporterTests
{
    [Fact]
    public async Task ExportAsync_WritesCmdFile_WhenSecretsPresent()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(tmp);

        try
        {
            var secrets = new StubSecretStore(
                loginServer: "  https://headscale.example  ",
                authKey: "  tskey-auth-123  ");

            var path = await TailscaleUpExporter.ExportAsync(
                secrets,
                baseDir: tmp,
                applyAcl: false,
                scope: Cerberus.Agent.Security.SecretStoreScope.User,
                ct: CancellationToken.None);

            var expectedPath = Path.Combine(tmp, "tailscale-up.cmd");
            Assert.Equal(expectedPath, path);
            Assert.True(File.Exists(expectedPath));

            var expected = TailscaleUpCommand.Build("https://headscale.example", "tskey-auth-123");
            var actual = await File.ReadAllTextAsync(expectedPath);
            Assert.Equal(expected, actual);
        }
        finally
        {
            try { Directory.Delete(tmp, recursive: true); } catch { }
        }
    }

    [Theory]
    [InlineData(null, "tskey-auth-123")]
    [InlineData("https://headscale.example", null)]
    [InlineData("  ", "tskey-auth-123")]
    [InlineData("https://headscale.example", "   ")]
    public async Task ExportAsync_ReturnsNull_WhenSecretsMissing(string? loginServer, string? authKey)
    {
        var tmp = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(tmp);

        try
        {
            var secrets = new StubSecretStore(loginServer, authKey);

            var path = await TailscaleUpExporter.ExportAsync(
                secrets,
                baseDir: tmp,
                applyAcl: false,
                scope: Cerberus.Agent.Security.SecretStoreScope.User,
                ct: CancellationToken.None);

            Assert.Null(path);
            Assert.False(File.Exists(Path.Combine(tmp, "tailscale-up.cmd")));
        }
        finally
        {
            try { Directory.Delete(tmp, recursive: true); } catch { }
        }
    }

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
        {
            throw new NotSupportedException();
        }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            return Task.FromResult((
                new AgentIdentity("a1", "t1"),
                "rt1",
                "priv",
                "http://backend",
                _loginServer,
                _authKey));
        }

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
