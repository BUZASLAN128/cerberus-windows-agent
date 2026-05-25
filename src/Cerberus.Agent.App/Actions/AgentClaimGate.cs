using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using System.Net;
using System.Net.Http;

namespace Cerberus.Agent.App.Actions;

internal static class AgentClaimGate
{
    private static readonly TimeSpan ClaimPollInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ClaimRetryPollInterval = TimeSpan.FromSeconds(20);
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
            HeartbeatResponse response;
            try
            {
                response = await CheckAsync(store, ct).ConfigureAwait(false);
            }
            catch (HttpRequestException ex) when (IsInactiveRegistrationStatus(ex.StatusCode))
            {
                await store.ClearAsync(ct).ConfigureAwait(false);
                throw new AgentRegistrationInactiveException($"http_{(int)ex.StatusCode!}");
            }
            catch (HttpRequestException ex) when (IsTransientClaimPollStatus(ex.StatusCode))
            {
                progress?.Invoke($"Portal claim check is temporarily rate limited or unavailable; retrying (status={(int)ex.StatusCode!}).");
                await Task.Delay(ClaimRetryPollInterval, ct).ConfigureAwait(false);
                continue;
            }
            var state = NormalizeState(response.RegistrationState);

            if (IsClaimed(response))
            {
                progress?.Invoke("Device claim confirmed. Continuing service setup...");
                return response;
            }

            if (state is "rejected" or "deactivated" or "revoked")
            {
                await store.ClearAsync(ct).ConfigureAwait(false);
                throw new AgentRegistrationInactiveException(state);
            }

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

        HeartbeatResponse response;
        try
        {
            response = CheckAsync(store, timeout.Token).GetAwaiter().GetResult();
        }
        catch (HttpRequestException ex) when (IsInactiveRegistrationStatus(ex.StatusCode))
        {
            store.ClearAsync(timeout.Token).GetAwaiter().GetResult();
            throw new AgentRegistrationInactiveException($"http_{(int)ex.StatusCode!}");
        }
        if (!IsClaimed(response))
        {
            var state = NormalizeState(response.RegistrationState);
            if (state is "rejected" or "deactivated" or "revoked")
            {
                store.ClearAsync(timeout.Token).GetAwaiter().GetResult();
                throw new AgentRegistrationInactiveException(state);
            }
            throw new InvalidOperationException($"Claim this device in the portal before installing the service (state={state}).");
        }
    }

    public static async Task<bool> ClearInactiveLocalRegistrationAsync(ISecretStore store, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ClaimCheckTimeout);

        HeartbeatResponse response;
        try
        {
            response = await CheckAsync(store, timeout.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException ex) when (IsInactiveRegistrationStatus(ex.StatusCode))
        {
            await store.ClearAsync(timeout.Token).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }

        var state = NormalizeState(response.RegistrationState);
        if (state is not ("rejected" or "deactivated" or "revoked"))
            return false;

        await store.ClearAsync(timeout.Token).ConfigureAwait(false);
        return true;
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
                runtime_mode = "interactive",
                supported_schema_versions = AgentSchemaVersions.All,
                tailscale = (object?)null,
                ad = (object?)null,
                capabilities = Array.Empty<string>(),
            },
            ct).ConfigureAwait(false);
    }

    private static string NormalizeState(string? state)
        => string.IsNullOrWhiteSpace(state) ? "pending_claim" : state.Trim().ToLowerInvariant();

    private static bool IsInactiveRegistrationStatus(HttpStatusCode? statusCode)
        => statusCode is HttpStatusCode.Unauthorized
            or HttpStatusCode.Forbidden
            or HttpStatusCode.NotFound
            or HttpStatusCode.Conflict;

    internal static bool IsTransientClaimPollStatus(HttpStatusCode? statusCode)
        => statusCode is HttpStatusCode.TooManyRequests
            or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;
}

internal sealed class AgentRegistrationInactiveException : InvalidOperationException
{
    public AgentRegistrationInactiveException(string state)
        : base($"Device registration is no longer claimable (state={state}).")
    {
        State = state;
    }

    public string State { get; }
}
