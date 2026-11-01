using Cerberus.Agent.App;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class ServiceCredentialReadTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TransientReadFailureRetriesWithoutChangingActiveRegistration(bool accessDenied)
    {
        var snapshot = new AgentLifecycleSnapshot { Generation = 1, LastEnrollmentNonce = Guid.NewGuid().ToString("N") };
        var lifecycle = new InMemoryAgentLifecycleStateStore(snapshot);
        var secrets = new TransientSecrets(accessDenied);
        var log = new RecordingLogger();
        if (accessDenied)
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => ServiceMode.LoadServiceCredentialsAsync(secrets, lifecycle, log, default));
        else
            await Assert.ThrowsAsync<IOException>(() => ServiceMode.LoadServiceCredentialsAsync(secrets, lifecycle, log, default));
        Assert.Equal(snapshot, await lifecycle.LoadAsync(default));
        var retry = new WorkerRestartBackoff();
        var now = DateTimeOffset.UtcNow;
        retry.OnWorkerEnded(now, now.AddMilliseconds(100), planned: false);
        Assert.False(retry.CanStart(now.AddSeconds(1)));
        Assert.True(retry.CanStart(now.AddMilliseconds(100) + WorkerRestartBackoff.InitialDelay));
        var loaded = await ServiceMode.LoadServiceCredentialsAsync(secrets, lifecycle, log, default);
        Assert.True(loaded.HasValue);
        Assert.Equal("agent-a", loaded.Value.Identity.AgentId);
        Assert.Equal(snapshot, await lifecycle.LoadAsync(default));
        Assert.Equal(2, secrets.Reads);
        Assert.Equal(0, secrets.Clears);
    }

    private sealed class TransientSecrets(bool accessDenied) : ISecretStore
    {
        public int Reads, Clears;
        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl,
            string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            if (++Reads == 1)
                throw accessDenied ? new UnauthorizedAccessException("Owned transient access fixture") : new IOException("Owned transient IO fixture");
            return Task.FromResult((new AgentIdentity("agent-a", "t1"), "owned", "owned", "https://backend.test", (string?)null, (string?)null));
        }
        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct) => throw new NotSupportedException();
        public Task ClearAsync(CancellationToken ct) { Clears++; return Task.CompletedTask; }
    }
}
