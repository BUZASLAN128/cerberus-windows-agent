using System.IO;
using System.Net.Http;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Control;

internal sealed class AgentLocalControlService
{
    private readonly IAgentLifecycleStateStore _lifecycle;
    private readonly Func<CancellationToken, Task> _quiesce;
    private readonly SemaphoreSlim _manual = new(1, 1);

    internal AgentLocalControlService(IAgentLifecycleStateStore lifecycle, Func<CancellationToken, Task> quiesce)
        => (_lifecycle, _quiesce) = (lifecycle, quiesce);

    internal async Task<AgentLocalControlResponse> HandleAsync(AgentLocalControlRequest request, CancellationToken ct)
    {
        if (request.Operation is "status" or "check" or "apply")
        {
            var response = await AgentUpdateLocalService.HandleAsync(request, ct).ConfigureAwait(false);
            var snapshot = await _lifecycle.LoadAsync(ct).ConfigureAwait(false);
            var awaitingAdoption = request.Operation == "status" && AgentEnrollmentPromotion.IsAwaitingAdoption(
                await AgentEnrollmentPromotion.ReadAsync(ct).ConfigureAwait(false), snapshot);
            return response with
            {
                Success = response.Success && !awaitingAdoption,
                LifecycleState = snapshot.State.ToString(),
                LifecycleGeneration = snapshot.Generation,
                Code = request.Operation == "status" ?
                    (!snapshot.QuiescenceComplete ? "cleanup_pending" : awaitingAdoption ? "enrollment_proof_required" : snapshot.ReasonCode ?? response.Code) : response.Code,
            };
        }
        if (!await _manual.WaitAsync(0, ct).ConfigureAwait(false))
            return new(false, "recovery_busy");
        try
        {
            return request.Operation switch
            {
                "retry" => await RetryAsync(ct).ConfigureAwait(false),
                "enrollment-adopt" => await AdoptAsync(ct).ConfigureAwait(false),
                "unregister" => await UnregisterAsync(ct).ConfigureAwait(false),
                _ => new(false, "invalid_request"),
            };
        }
        catch (Exception ex) when (ex is HttpRequestException or AgentLifecycleDormantException or IOException or
            UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException)
        {
            var snapshot = await _lifecycle.LoadAsync(ct).ConfigureAwait(false);
            return StateResponse(false, snapshot.ReasonCode ?? "recovery_failed", snapshot);
        }
        finally { _manual.Release(); }
    }

    private async Task<AgentLocalControlResponse> RetryAsync(CancellationToken ct)
    {
        var store = new DpapiSecretStore(SecretStoreScope.Machine);
        var controller = new AgentLifecycleController(_lifecycle, store, quiesce: _quiesce);
        var snapshot = await controller.CompletePendingQuiescenceAsync(ct).ConfigureAwait(false);
        if (!snapshot.QuiescenceComplete)
            return StateResponse(false, "cleanup_pending", snapshot);
        if (snapshot.State is AgentLifecycleState.Retired or AgentLifecycleState.NeedsReenrollment)
            return StateResponse(false, snapshot.ReasonCode == AgentLifecycleStatePolicy.AgentRevokedCode ? "contact_admin" : "reenrollment_required", snapshot);
        if (snapshot.NextAttemptUtc > DateTimeOffset.UtcNow)
            return StateResponse(false, "retry_deferred", snapshot);
        if (snapshot.State == AgentLifecycleState.Active)
            return StateResponse(true, "already_active", snapshot);
        var response = await ProbeAsync(store, _lifecycle, _quiesce, ct).ConfigureAwait(false);
        if (!Claimed(response))
            return StateResponse(false, "registration_not_claimed", await _lifecycle.LoadAsync(ct).ConfigureAwait(false));
        var recovered = await controller.CompleteManualRecoveryAsync(snapshot.Generation, ct).ConfigureAwait(false);
        return StateResponse(AgentLifecycleStates.AllowsAutomaticNetwork(recovered.State), "recovery_checked", recovered);
    }

    private async Task<AgentLocalControlResponse> UnregisterAsync(CancellationToken ct)
    {
        var machine = new DpapiSecretStore(SecretStoreScope.Machine);
        var controller = new AgentLifecycleController(_lifecycle, machine, quiesce: _quiesce);
        var snapshot = await controller.CompletePendingQuiescenceAsync(ct).ConfigureAwait(false);
        if (!snapshot.QuiescenceComplete)
            return StateResponse(false, "cleanup_pending", snapshot);
        if (snapshot.State == AgentLifecycleState.Retired)
            return StateResponse(true, "registration_retired", snapshot);
        if (snapshot.State == AgentLifecycleState.NeedsReenrollment)
            return StateResponse(false, "reenrollment_required", snapshot);
        var (_, _, key, backend, _, _) = await machine.LoadAsync(ct).ConfigureAwait(false);
        using var http = new HttpClient { BaseAddress = new Uri(backend), Timeout = TimeSpan.FromSeconds(30) };
        var api = new AgentApiClient(http, machine,
            new AgentTokenManager(http, machine, lifecycleState: _lifecycle, manualOperation: true, quiesce: _quiesce),
            new RequestSigner(key), _lifecycle, manualOperation: true, quiesce: _quiesce);
        await api.SelfDeactivateAsync(new AgentSelfDeactivateRequest("agent.self-deactivate.v1",
            "agent_unregister_device", "Device unregistered from Windows agent"), ct).ConfigureAwait(false);
        try { await controller.RetireAsync(AgentLifecycleStatePolicy.AgentDeactivatedCode, null, ct).ConfigureAwait(false); }
        catch (AgentRetiredException) { }
        var retired = await _lifecycle.LoadAsync(ct).ConfigureAwait(false);
        return StateResponse(retired.State == AgentLifecycleState.Retired && retired.QuiescenceComplete,
            retired.QuiescenceComplete ? "registration_retired" : "cleanup_pending", retired);
    }

    private async Task<AgentLocalControlResponse> AdoptAsync(CancellationToken ct)
    {
        var snapshot = await _lifecycle.LoadAsync(ct).ConfigureAwait(false);
        if (!snapshot.QuiescenceComplete || snapshot.ReasonCode == AgentLifecycleStatePolicy.AgentRevokedCode)
            return StateResponse(false, snapshot.QuiescenceComplete ? "contact_admin" : "cleanup_pending", snapshot);
        var marker = await AgentEnrollmentPromotion.ReadAsync(ct).ConfigureAwait(false);
        if (marker is null || marker.ExpectedGeneration != snapshot.Generation || marker.Nonce == snapshot.LastEnrollmentNonce)
            return StateResponse(false, "enrollment_proof_required", snapshot);
        var pending = AgentEnrollmentPromotion.OpenProbeStore(marker);
        if (!await AgentEnrollmentPromotion.MatchesAsync(marker, pending, ct).ConfigureAwait(false))
            return StateResponse(false, "enrollment_identity_mismatch", snapshot);
        // This is one explicit enrollment validation, never an automatic retry
        // through the dormant gate. Failed validation cannot rewrite machine state.
        var probeState = new InMemoryAgentLifecycleStateStore();
        var response = await ProbeAsync(pending, probeState, quiesce: null, ct).ConfigureAwait(false);
        if (!Claimed(response) || AgentLifecycleStates.IsDormant((await probeState.LoadAsync(ct).ConfigureAwait(false)).State))
            return StateResponse(false, "enrollment_validation_failed", snapshot);

        using var fence = await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false);
        var currentMarker = await AgentEnrollmentPromotion.ReadAsync(ct).ConfigureAwait(false);
        var current = await _lifecycle.LoadAsync(ct).ConfigureAwait(false);
        if (currentMarker != marker || current.Generation != snapshot.Generation || !current.QuiescenceComplete ||
            current.ReasonCode == AgentLifecycleStatePolicy.AgentRevokedCode ||
            !await AgentEnrollmentPromotion.MatchesAsync(marker, AgentEnrollmentPromotion.OpenPendingStore(), ct).ConfigureAwait(false))
            return StateResponse(false, "enrollment_proof_stale", current);
        if (_lifecycle is not DurableAgentLifecycleStateStore durable)
            throw new InvalidOperationException("Machine enrollment requires the durable lifecycle authority.");
        var adopted = await durable.CommitEnrollmentAsync(current.Generation, marker.Nonce,
            cancel => AgentCredentialPublication.BeginAsync(durable, current.Generation, marker.Nonce, cancel), ct).ConfigureAwait(false);
        return StateResponse(true, "enrollment_adopted", adopted);
    }

    private static async Task<HeartbeatResponse> ProbeAsync(ISecretStore store, IAgentLifecycleStateStore lifecycle,
        Func<CancellationToken, Task>? quiesce, CancellationToken ct)
    {
        _ = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
        var (_, _, key, backend, _, _) = await store.LoadAsync(ct).ConfigureAwait(false);
        if (!Uri.TryCreate(backend, UriKind.Absolute, out var endpoint) || endpoint.Scheme is not ("https" or "http"))
            throw new InvalidDataException("Stored endpoint is invalid.");
        using var http = new HttpClient { BaseAddress = endpoint, Timeout = TimeSpan.FromSeconds(30) };
        var api = new AgentApiClient(http, store,
            new AgentTokenManager(http, store, lifecycleState: lifecycle, manualOperation: true, quiesce: quiesce),
            new RequestSigner(key), lifecycle, manualOperation: true, quiesce: quiesce);
        var response = await api.HeartbeatAsync(CreateManualHeartbeat(), ct).ConfigureAwait(false);
        await new HeartbeatResponseHandler(store, lifecycleState: lifecycle, quiesce: quiesce)
            .HandleAsync(response, ct).ConfigureAwait(false);
        return response;
    }

    // Manual recovery is still a service heartbeat on the canonical backend wire contract.
    internal static object CreateManualHeartbeat() => new
        {
            status = "connected",
            agent_version = WindowsDeviceInfo.GetAgentVersion(),
            build_id = WindowsDeviceInfo.GetBuildId(),
            build_channel = WindowsDeviceInfo.GetBuildChannel(),
            runtime_mode = "service",
            supported_schema_versions = AgentSchemaVersions.All,
            capabilities = Array.Empty<string>(),
        };

    private static bool Claimed(HeartbeatResponse response)
        => response.RegistrationState == "claimed" && !response.ClaimRequired &&
            response.LifecycleState is not ("revoked" or "quarantined") &&
            !(response.Revoke?.TryGetValue("revoked", out var revoked) == true && revoked.ValueKind == System.Text.Json.JsonValueKind.True);

    private static AgentLocalControlResponse StateResponse(bool success, string code, AgentLifecycleSnapshot state)
        => new(success, code, LifecycleState: state.State.ToString(), LifecycleGeneration: state.Generation);
}
