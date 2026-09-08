using System.Text.Json;

namespace Cerberus.Agent.Core;

public enum HeartbeatControlAction
{
    Continue,
    SkipCommands,
    Stop,
}

public sealed class HeartbeatResponseHandler
{
    private readonly ISecretStore _secrets;
    private readonly IAgentLogger _log;
    private readonly IAgentUpdateCoordinator? _updates;
    private readonly Func<HeartbeatResponse, Exception, CancellationToken, Task>? _updateFailureReporter;
    private readonly IAgentLifecycleStateStore _lifecycleState;
    private readonly Func<CancellationToken, Task>? _quiesce;
    private readonly ManagedAccountManifestPolicy? _managedAccounts;

    public HeartbeatResponseHandler(
        ISecretStore secrets,
        IAgentLogger? log = null,
        IAgentUpdateCoordinator? updates = null,
        Func<HeartbeatResponse, Exception, CancellationToken, Task>? updateFailureReporter = null,
        IAgentLifecycleStateStore? lifecycleState = null,
        Func<CancellationToken, Task>? quiesce = null,
        ManagedAccountManifestPolicy? managedAccounts = null)
    {
        _secrets = secrets;
        _log = log ?? NullAgentLogger.Instance;
        _updates = updates;
        _updateFailureReporter = updateFailureReporter;
        // Production service callers pass the protected durable store. The
        // in-memory fallback keeps legacy/support callers on the same
        // terminal-code gate without allowing a raw response to clear secrets.
        _lifecycleState = lifecycleState ?? new InMemoryAgentLifecycleStateStore();
        _quiesce = quiesce;
        _managedAccounts = managedAccounts;
    }

    public async Task<HeartbeatControlAction> HandleAsync(HeartbeatResponse response, CancellationToken ct)
    {
        var generation = AgentApiClient.GenerationOf(response);
        var current = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        if (generation is not null && current.Generation != generation)
            return HeartbeatControlAction.Stop;
        await PersistUiContextAsync(response, ct).ConfigureAwait(false);

        if (response.Revoke is not null &&
            IsTrue(response.Revoke, "revoked") &&
            IsTrue(response.Revoke, "clear_local_credentials"))
        {
            if (HasClearConfirmation(response.Revoke))
            {
                var reasonCode = TerminalReasonCode(response.Revoke);
                if (reasonCode is null)
                {
                    _log.Warn("remote_clear_ignored_requires_terminal_code: revoke reason code is not approved.");
                    return HeartbeatControlAction.Continue;
                }
                try
                {
                    await new AgentLifecycleController(_lifecycleState, _secrets, quiesce: _quiesce)
                        .RecordTerminalResponseAsync(reasonCode, requestId: null, ct, expectedGeneration: generation)
                        .ConfigureAwait(false);
                }
                catch (AgentRetiredException)
                {
                    // Retired state is the expected terminal outcome.
                }
                _log.Warn("Agent terminal intent recorded; automatic network is paused.");
            }
            else
            {
                _log.Warn(
                    "remote_clear_ignored_requires_confirmation: revoke requested local credential clear without explicit confirmation.");
                return HeartbeatControlAction.Continue;
            }
            return HeartbeatControlAction.Stop;
        }

        if (AgentLifecycleStates.IsDormant(current.State) || !current.QuiescenceComplete)
            return HeartbeatControlAction.Stop;

        if (response.Quarantine is not null && IsTrue(response.Quarantine, "active"))
        {
            _log.Warn("Agent quarantined by server policy; skipping command execution.");
            return HeartbeatControlAction.SkipCommands;
        }

        if (string.Equals(response.LifecycleState, "upgrading", StringComparison.Ordinal) ||
            string.Equals(response.AgentStatus, "upgrade_required", StringComparison.Ordinal))
        {
            await TryHandleUpdateAsync(response, ct).ConfigureAwait(false);
            return HeartbeatControlAction.SkipCommands;
        }

        if (_managedAccounts is not null)
            await _managedAccounts.RefreshAsync(response, ct).ConfigureAwait(false);
        await TryHandleUpdateAsync(response, ct).ConfigureAwait(false);
        return HeartbeatControlAction.Continue;
    }

    private async Task PersistUiContextAsync(HeartbeatResponse response, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(response.TenantName))
            return;

        try
        {
            var (identity, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
            await AgentUiContextStore.WriteBestEffortAsync(
                identity,
                response.TenantName,
                accountLabel: null,
                ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Warn($"Agent UI context update failed: {ex.GetType().Name}");
        }
    }

    private async Task TryHandleUpdateAsync(HeartbeatResponse response, CancellationToken ct)
    {
        if (_updates is null || response.Update is null)
            return;

        try
        {
            await _updates.HandleUpdateAsync(response, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Warn($"Agent update handling failed: {ex.GetType().Name}: {ex.Message}");
            if (_updateFailureReporter is null)
                return;

            try
            {
                await _updateFailureReporter(response, ex, ct).ConfigureAwait(false);
            }
            catch (Exception reporterEx)
            {
                _log.Warn($"Agent update failure reporting failed: {reporterEx.GetType().Name}: {reporterEx.Message}");
            }
        }
    }

    private static bool IsTrue(IReadOnlyDictionary<string, JsonElement> values, string key)
    {
        if (!values.TryGetValue(key, out var element))
            return false;
        return element.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.String => bool.TryParse(element.GetString(), out var parsed) && parsed,
            _ => false,
        };
    }

    private static bool HasClearConfirmation(IReadOnlyDictionary<string, JsonElement> values)
        => values.TryGetValue("clear_local_credentials_confirmation", out var element) &&
           element.ValueKind == JsonValueKind.String &&
           string.Equals(
               element.GetString(),
               "cerberus-agent-clear-local-credentials-v1",
               StringComparison.Ordinal);

    private static string? TerminalReasonCode(IReadOnlyDictionary<string, JsonElement> values)
    {
        if (values.TryGetValue("reason_code", out var element))
        {
            if (element.ValueKind != JsonValueKind.String)
                return null;
            var code = element.GetString()?.Trim();
            return AgentLifecycleStatePolicy.IsTerminalCode(code) ? code : null;
        }

        return null;
    }
}
