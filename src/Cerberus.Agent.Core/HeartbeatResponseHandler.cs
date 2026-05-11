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

    public HeartbeatResponseHandler(
        ISecretStore secrets,
        IAgentLogger? log = null,
        IAgentUpdateCoordinator? updates = null,
        Func<HeartbeatResponse, Exception, CancellationToken, Task>? updateFailureReporter = null)
    {
        _secrets = secrets;
        _log = log ?? NullAgentLogger.Instance;
        _updates = updates;
        _updateFailureReporter = updateFailureReporter;
    }

    public async Task<HeartbeatControlAction> HandleAsync(HeartbeatResponse response, CancellationToken ct)
    {
        if (response.Revoke is not null &&
            IsTrue(response.Revoke, "revoked") &&
            IsTrue(response.Revoke, "clear_local_credentials"))
        {
            if (HasClearConfirmation(response.Revoke))
            {
                await _secrets.ClearAsync(ct).ConfigureAwait(false);
                _log.Warn("Agent revoked by server policy; local credentials cleared after explicit confirmation.");
            }
            else
            {
                _log.Warn(
                    "remote_clear_ignored_requires_confirmation: revoke requested local credential clear without explicit confirmation.");
            }
            return HeartbeatControlAction.Stop;
        }

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

        await TryHandleUpdateAsync(response, ct).ConfigureAwait(false);
        return HeartbeatControlAction.Continue;
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
}
