using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public sealed record ManagedAccountEntry(
    [property: JsonPropertyName("assignment_id")] string AssignmentId,
    [property: JsonPropertyName("managed_account_id")] string ManagedAccountId,
    [property: JsonPropertyName("user_id")] string UserId,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("marker_id")] string MarkerId,
    [property: JsonPropertyName("status")] string Status);

public sealed record ManagedAccountManifest(
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("hash")] string Hash,
    [property: JsonPropertyName("fresh_until")] DateTimeOffset FreshUntil,
    [property: JsonPropertyName("require_manifest_before_unlock")] bool RequireManifestBeforeUnlock,
    [property: JsonPropertyName("accounts")] IReadOnlyList<ManagedAccountEntry> Accounts);

public interface IManagedAccountReconciler
{
    // Only fully bound, SID-verified local accounts are eligible for disabling.
    Task ReconcileAsync(AgentIdentity identity, IReadOnlyList<ManagedAccountEntry> allowed, CancellationToken ct);
}

public interface ICommandExecutionGate
{
    Task<CommandResult> ExecuteAuthorizedAsync(AgentCommand command, Func<Task<CommandResult>> execute, CancellationToken ct);
    Task<CommandResult> HandleAuthorizedAsync(AgentCommand command, CancellationToken ct);
}

/// <summary>Serializes authority refresh with enabling, including cached command results.
/// Authority is memory-only: service restart always requires a fresh heartbeat and manifest.</summary>
public sealed class ManagedAccountManifestPolicy
{
    private readonly AgentIdentity _identity;
    private readonly IAgentLifecycleStateStore _lifecycle;
    private readonly Func<CancellationToken, Task<ManagedAccountManifest>> _fetch;
    private readonly IManagedAccountReconciler _accounts;
    private readonly IAgentLogger _log;
    private readonly Func<DateTimeOffset> _now;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private ManagedAccountManifest? _manifest;
    private long _generation;
    private DateTimeOffset _freshUntil;
    private DateTimeOffset _nextFetch;

    public ManagedAccountManifestPolicy(AgentIdentity identity, IAgentLifecycleStateStore lifecycle,
        Func<CancellationToken, Task<ManagedAccountManifest>> fetch, IManagedAccountReconciler accounts,
        IAgentLogger? log = null, Func<DateTimeOffset>? now = null)
    {
        _identity = identity;
        _lifecycle = lifecycle;
        _fetch = fetch;
        _accounts = accounts;
        _log = log ?? NullAgentLogger.Instance;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public AgentIdentity Identity => _identity;

    public async Task RefreshAsync(HeartbeatResponse heartbeat, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var lifecycle = await _lifecycle.LoadAsync(ct).ConfigureAwait(false);
            var previous = _manifest;
            _manifest = null;
            if (AgentLifecycleStates.IsDormant(lifecycle.State) || !lifecycle.QuiescenceComplete ||
                AgentApiClient.GenerationOf(heartbeat) is long responseGeneration && responseGeneration != lifecycle.Generation)
                return;
            _generation = lifecycle.Generation;
            if (heartbeat.RequireManifestBeforeUnlock && !heartbeat.ClaimRequired &&
                DateTimeOffset.TryParse(heartbeat.ManifestFreshUntil, CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var freshUntil) && freshUntil > _now() &&
                freshUntil <= _now().AddSeconds(300) && !string.IsNullOrWhiteSpace(heartbeat.ManifestVersion) &&
                !string.IsNullOrWhiteSpace(heartbeat.ManagedAccountManifestHash))
            {
                ManagedAccountManifest? candidate = previous;
                if (_now() >= _nextFetch && (candidate is null || candidate.Hash != heartbeat.ManagedAccountManifestHash ||
                    candidate.Version != heartbeat.ManifestVersion || candidate.FreshUntil <= _now()))
                {
                    try
                    {
                        candidate = await _fetch(ct).ConfigureAwait(false);
                        _nextFetch = DateTimeOffset.MinValue;
                    }
                    catch (Exception ex) when (ex is not AgentLifecycleDormantException &&
                        (ex is HttpRequestException or InvalidOperationException or JsonException ||
                         ex is OperationCanceledException && !ct.IsCancellationRequested))
                    {
                        candidate = null;
                        _nextFetch = _now().AddSeconds(60);
                        _log.Warn("managed_account_manifest_unavailable: enabling denied.");
                    }
                }
                if (candidate is not null && candidate.FreshUntil > _now() &&
                    candidate.FreshUntil <= _now().AddSeconds(300) && candidate.RequireManifestBeforeUnlock &&
                    candidate.Version == heartbeat.ManifestVersion && candidate.Hash == heartbeat.ManagedAccountManifestHash &&
                    IsValid(candidate))
                {
                    _manifest = candidate;
                    _freshUntil = candidate.FreshUntil < freshUntil ? candidate.FreshUntil : freshUntil;
                }
                else if (candidate is not null && _now() >= _nextFetch)
                {
                    _nextFetch = _now().AddSeconds(60);
                }
            }
            // The lifecycle lock binds the entire local mutation to this enrollment generation.
            try
            {
                await _lifecycle.ExecuteIfCurrentAsync(_generation, cancel => _accounts.ReconcileAsync(
                    _identity, _manifest?.Accounts ?? Array.Empty<ManagedAccountEntry>(), cancel), ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not AgentLifecycleDormantException &&
                ex is IOException or UnauthorizedAccessException or InvalidOperationException or
                    System.Security.SecurityException or System.Runtime.InteropServices.COMException)
            {
                _manifest = null;
                _log.Warn("managed_account_manifest_reconciliation_unavailable: enabling denied; explicit safety commands remain available.");
            }
        }
        finally { _gate.Release(); }
    }

    public Task<CommandResult> ExecuteAuthorizedAsync(ManagedAccountEntry requested,
        Func<Task<CommandResult>> execute, CancellationToken ct)
        => ExecuteAuthorizedAsync(requested, enableAccount: true, enableAccountExplicit: false, execute, ct);

    public async Task<CommandResult> ExecuteAuthorizedAsync(ManagedAccountEntry requested,
        bool enableAccount, bool enableAccountExplicit, Func<Task<CommandResult>> execute, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            AgentLifecycleSnapshot lifecycle;
            try
            {
                lifecycle = await _lifecycle.LoadAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ExpectedLifecycleFailure(ex, ct))
            {
                _log.Warn("managed_account_manifest_lifecycle_unavailable: mutation denied.");
                return Denied(requested, "unknown");
            }

            if (_manifest is null || _freshUntil <= _now() || lifecycle.Generation != _generation ||
                AgentLifecycleStates.IsDormant(lifecycle.State) || !lifecycle.QuiescenceComplete ||
                !_manifest.Accounts.Any(entry => AllowsMutation(entry, enableAccount, enableAccountExplicit) &&
                    entry.AssignmentId == requested.AssignmentId &&
                    entry.ManagedAccountId == requested.ManagedAccountId && entry.UserId == requested.UserId &&
                    entry.Username == requested.Username && entry.MarkerId == requested.MarkerId))
                return Denied(requested, "before_execution");

            CommandResult result = Denied(requested, "before_execution");
            var callbackStarted = false;
            try
            {
                var entered = await _lifecycle.ExecuteIfCurrentAsync(_generation, async cancel =>
                {
                    cancel.ThrowIfCancellationRequested();
                    if (_freshUntil <= _now()) return;
                    callbackStarted = true;
                    result = await execute().ConfigureAwait(false);
                    // A slow SAM operation must not leave an enabled account after its lease expired.
                    if (_freshUntil <= _now())
                    {
                        _manifest = null;
                        var compensationStatus = "attempted";
                        try
                        {
                            await _accounts.ReconcileAsync(_identity, Array.Empty<ManagedAccountEntry>(),
                                CancellationToken.None).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            _ = ex;
                            compensationStatus = "failed";
                            _log.Warn("managed_account_manifest_expiry_compensation_failed");
                        }

                        result = Denied(requested, ExpiryExecutionStage(result), result, compensationStatus);
                    }
                }, ct).ConfigureAwait(false);
                return entered
                    ? result
                    : Denied(requested, "before_execution");
            }
            catch (Exception ex) when (ExpectedLifecycleFailure(ex, ct))
            {
                _log.Warn("managed_account_manifest_lifecycle_changed: mutation denied.");
                return Denied(requested, callbackStarted ? "unknown" : "before_execution");
            }
        }
        finally { _gate.Release(); }
    }

    public static CommandResult Denied() => Denied(null, "before_execution");

    public static CommandResult Denied(ManagedAccountEntry? requested, string executionStage,
        CommandResult? mutationResult = null, string? compensationStatus = null)
        => new(
            "FAILED",
            2,
            null,
            "Fresh managed account manifest authority is required.",
            new
            {
                code = "managed_account_manifest_required",
                username = requested?.Username,
                managed_account_id = requested?.ManagedAccountId,
                assignment_id = requested?.AssignmentId,
                marker_id = requested?.MarkerId,
                execution_stage = executionStage,
                mutation_result_code = ReadPostVerifyString(mutationResult?.PostVerify, "code"),
                mutation_result_status = mutationResult?.Status,
                compensation_status = compensationStatus,
            });

    private static bool IsValid(ManagedAccountManifest manifest)
    {
        if (manifest.Accounts is null || manifest.Accounts.Any(a => a is null ||
            new[] { a.AssignmentId, a.ManagedAccountId, a.UserId, a.Username, a.MarkerId }.Any(string.IsNullOrWhiteSpace) ||
            string.IsNullOrWhiteSpace(a.Status)) ||
            manifest.Accounts.Select(a => a.AssignmentId).Distinct(StringComparer.Ordinal).Count() != manifest.Accounts.Count ||
            manifest.Accounts.Select(a => a.Username).Distinct(StringComparer.OrdinalIgnoreCase).Count() != manifest.Accounts.Count)
            return false;
        // Match Python json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=True).
        var entries = manifest.Accounts.OrderBy(a => a.AssignmentId, StringComparer.Ordinal).Select(a =>
            "{\"assignment_id\":" + Quote(a.AssignmentId) + ",\"managed_account_id\":" + Quote(a.ManagedAccountId) +
            ",\"marker_id\":" + Quote(a.MarkerId) + ",\"status\":" + Quote(a.Status) +
            ",\"user_id\":" + Quote(a.UserId) + ",\"username\":" + Quote(a.Username) + "}");
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("[" + string.Join(",", entries) + "]"))).ToLowerInvariant();
        return hash == manifest.Hash && manifest.Version == hash[..16];
    }

    private static string Quote(string value)
    {
        var json = new StringBuilder("\"");
        foreach (var c in value)
            json.Append(c switch
            {
                '"' => "\\\"", '\\' => "\\\\", '\b' => "\\b", '\f' => "\\f",
                '\n' => "\\n", '\r' => "\\r", '\t' => "\\t",
                _ when c < 32 || c >= 127 => "\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture),
                _ => c.ToString()
            });
        return json.Append('"').ToString();
    }

    public static bool Allows(ManagedAccountEntry entry) => entry.Status is "planned" or "create_queued" or "active";

    private static bool AllowsMutation(ManagedAccountEntry entry, bool enableAccount, bool enableAccountExplicit)
        => Allows(entry) || entry.Status == "disabled_rotate_queued" && enableAccountExplicit && !enableAccount;

    private static string? ReadPostVerifyString(object? postVerify, string name)
    {
        if (postVerify is null) return null;
        if (postVerify is JsonElement element && element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(name, out var property))
            return property.ValueKind == JsonValueKind.String ? property.GetString() : property.ToString();
        var reflected = postVerify.GetType().GetProperty(name);
        return reflected?.GetValue(postVerify)?.ToString();
    }

    private static string ExpiryExecutionStage(CommandResult result)
    {
        var stage = ReadPostVerifyString(result.PostVerify, "execution_stage");
        if (string.Equals(stage, "after_execution", StringComparison.Ordinal))
            return "after_execution";

        // Legacy successful local results predate execution_stage. A DONE
        // result is the only safe compatibility signal that native mutation
        // completed; FAILED results remain conservative after compensation.
        return result.Status == "DONE" ? "after_execution" : "unknown";
    }

    private static bool ExpectedLifecycleFailure(Exception ex, CancellationToken ct)
        => ex is AgentLifecycleDormantException or IOException or UnauthorizedAccessException or
            InvalidOperationException or System.Security.SecurityException or System.Runtime.InteropServices.COMException ||
            ex is OperationCanceledException && !ct.IsCancellationRequested;

}
