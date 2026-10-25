using System.Net;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Support evidence: a heartbeat answered under an older lifecycle generation stops the loop and neither
// retires nor clears the newer registration, even when the response carries a confirmed revoke.
public sealed class HeartbeatResponseHandlerGenerationTests
{
    private const string RevokeResponse =
        """
        {"pending_commands":[],"next_poll_seconds":60,"next_snapshot_seconds":300,
         "revoke":{"revoked":true,"clear_local_credentials":true,
                   "clear_local_credentials_confirmation":"cerberus-agent-clear-local-credentials-v1","reason_code":"agent_revoked"}}
        """;

    [Fact]
    public async Task GenerationBumpedAfterTheHeartbeatWasSent_StopsWithoutRetiringOrClearing()
    {
        var f = await HeartbeatAsync();
        var current = await f.State.LoadAsync(default);
        Assert.NotNull(await f.State.TrySaveAsync(current with { Generation = current.Generation + 1 }, current.Revision, default));

        var action = await f.Handler.HandleAsync(f.Response, default);

        Assert.Equal(HeartbeatControlAction.Stop, action);
        Assert.Equal(AgentLifecycleState.Active, (await f.State.LoadAsync(default)).State);
        Assert.False(f.Secrets.Cleared);
    }

    [Fact]
    public async Task SameGeneration_ContinuesWithoutARevoke()
    {
        var f = await HeartbeatAsync("""{"pending_commands":[],"next_poll_seconds":60,"next_snapshot_seconds":300}""");

        Assert.Equal(HeartbeatControlAction.Continue, await f.Handler.HandleAsync(f.Response, default));
    }

    private static async Task<(HeartbeatResponseHandler Handler, HeartbeatResponse Response, InMemoryAgentLifecycleStateStore State, Secrets Secrets)> HeartbeatAsync(string json = RevokeResponse)
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new Secrets();
        using var http = new HttpClient(new Backend(json)) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, secrets, new Token(), new Signer(), lifecycleState: state);
        var response = await client.HeartbeatAsync(new { a = 1 }, default);
        return (new HeartbeatResponseHandler(secrets, lifecycleState: state), response, state, secrets);
    }

    private sealed class Backend(string json) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            });
    }

    private sealed class Secrets : ISecretStore
    {
        public bool Cleared { get; private set; }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((new AgentIdentity("agent-a", "t1"), "refresh", "key", "http://backend.test", (string?)null, (string?)null));

        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
            => Task.CompletedTask;

        public Task ClearAsync(CancellationToken ct)
        {
            Cleared = true;
            return Task.CompletedTask;
        }
    }

    private sealed class Token : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("token");

        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class Signer : IRequestSigner
    {
        public string ComputeBodyHash(byte[] bodyBytes) => "hash";

        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash)
            => $"{method}:{path}:{nonce}:{timestamp}:{bodyHash}";

        public string Sign(string canonical) => "signature";
    }
}
