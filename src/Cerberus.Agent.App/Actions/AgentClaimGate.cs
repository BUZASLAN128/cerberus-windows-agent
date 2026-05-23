using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using System.Net.Http;

namespace Cerberus.Agent.App.Actions;

internal static class AgentClaimGate
{
    private static readonly TimeSpan ClaimPollInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ClaimWaitTimeout = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan ClaimCheckTimeout = TimeSpan.FromSeconds(30);

    public static async Task<HeartbeatResponse> WaitForClaimedAsync(
        ISecretStore store,
        Action<string>? progress,
        CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow.Add(ClaimWaitTimeout);
        var lastState = "";
        var lastStatusAt = DateTimeOffset.MinValue;

        progress?.Invoke("Device registered. Open the portal and click 'Kilitle ve devam et' for this device.");

        while (DateTimeOffset.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            var response = await CheckAsync(store, ct).ConfigureAwait(false);
            var state = NormalizeState(response.RegistrationState);

            if (IsClaimed(response))
            {
                progress?.Invoke("Device claim confirmed. Continuing service setup...");
                return response;
            }

            if (state is "rejected" or "deactivated" or "revoked")
                throw new InvalidOperationException($"Device registration is no longer claimable (state={state}).");

            var now = DateTimeOffset.UtcNow;
            if (!string.Equals(state, lastState, StringComparison.Ordinal) || now - lastStatusAt >= TimeSpan.FromSeconds(30))
            {
                progress?.Invoke($"Waiting for portal claim (state={state}).");
                lastState = state;
                lastStatusAt = now;
            }

            await Task.Delay(ClaimPollInterval, ct).ConfigureAwait(false);
        }

        throw new InvalidOperationException("Device was not claimed in the portal before the setup timeout.");
    }

    public static void RequireClaimedForServiceInstall(ISecretStore store, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ClaimCheckTimeout);

        var response = CheckAsync(store, timeout.Token).GetAwaiter().GetResult();
        if (!IsClaimed(response))
        {
            var state = NormalizeState(response.RegistrationState);
            throw new InvalidOperationException($"Claim this device in the portal before installing the service (state={state}).");
        }
    }

    internal static bool IsClaimed(HeartbeatResponse response)
        => string.Equals(NormalizeState(response.RegistrationState), "claimed", StringComparison.Ordinal)
           && !response.ClaimRequired;

    private static async Task<HeartbeatResponse> CheckAsync(ISecretStore store, CancellationToken ct)
    {
        var (_, _, privateKeyPem, backendUrl, _, _) = await store.LoadAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(privateKeyPem) || string.IsNullOrWhiteSpace(backendUrl))
            throw new InvalidOperationException("Agent registration is incomplete.");

        using var http = new HttpClient
        {
            BaseAddress = new Uri(backendUrl.TrimEnd('/')),
            Timeout = ClaimCheckTimeout,
        };
        var api = new AgentApiClient(
            http,
            store,
            new AgentTokenManager(http, store),
            new RequestSigner(privateKeyPem));

        return await api.HeartbeatAsync(
            new
            {
                status = "connected",
                agent_version = WindowsDeviceInfo.GetAgentVersion(),
                build_id = WindowsDeviceInfo.GetBuildId(),
                build_channel = WindowsDeviceInfo.GetBuildChannel(),
                runtime_mode = "setup",
                supported_schema_versions = AgentSchemaVersions.All,
                tailscale = (object?)null,
                ad = (object?)null,
                capabilities = Array.Empty<string>(),
            },
            ct).ConfigureAwait(false);
    }

    private static string NormalizeState(string? state)
        => string.IsNullOrWhiteSpace(state) ? "pending_claim" : state.Trim().ToLowerInvariant();
}
