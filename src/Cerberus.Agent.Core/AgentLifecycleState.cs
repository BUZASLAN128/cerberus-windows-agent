using System.Net;

namespace Cerberus.Agent.Core;

/// <summary>
/// Durable local state that gates automatic agent network activity.
/// </summary>
public enum AgentLifecycleState
{
    Active = 0,
    AuthSuspect = 1,
    BlockedConfig = 2,
    NeedsReenrollment = 3,
    Retired = 4,
    // Appended to preserve the numeric meaning of states already written by
    // older in-memory/diagnostic callers. Durable files serialize the name.
    Degraded = 5,
}

public static class AgentLifecycleStates
{
    public static bool AllowsAutomaticNetwork(AgentLifecycleState state)
        => state is AgentLifecycleState.Active or AgentLifecycleState.Degraded;

    public static bool IsDormant(AgentLifecycleState state)
        => !AllowsAutomaticNetwork(state);
}

/// <summary>
/// Non-secret lifecycle metadata. The state store must never contain tokens,
/// private keys, response bodies, or other credential material.
/// </summary>
public sealed record AgentLifecycleSnapshot(
    AgentLifecycleState State = AgentLifecycleState.Active,
    string? ReasonCode = null,
    string? LastRequestId = null,
    DateTimeOffset? NextAttemptUtc = null,
    int GenericAuthFailureCount = 0,
    DateTimeOffset? UpdatedAtUtc = null)
{
    public DateTimeOffset EffectiveUpdatedAtUtc => UpdatedAtUtc ?? DateTimeOffset.UtcNow;
}

public interface IAgentLifecycleStateStore
{
    Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct);
    Task SaveAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct);
}

/// <summary>
/// Small in-memory implementation useful for support tests and callers that do
/// not need process-restart persistence. Production service mode uses the
/// protected durable implementation from the security project.
/// </summary>
public sealed class InMemoryAgentLifecycleStateStore : IAgentLifecycleStateStore
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private AgentLifecycleSnapshot _snapshot = new();

    public InMemoryAgentLifecycleStateStore(AgentLifecycleSnapshot? initial = null)
    {
        _snapshot = initial ?? new AgentLifecycleSnapshot();
    }

    public async Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return _snapshot;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            _snapshot = AgentLifecycleStatePolicy.Normalize(snapshot);
        }
        finally
        {
            _gate.Release();
        }
    }
}

public static class AgentLifecycleStatePolicy
{
    public const string AgentDeactivatedCode = "agent_deactivated";
    public const string AgentRevokedCode = "agent_revoked";

    public static bool IsTerminalCode(string? code)
        => string.Equals(code, AgentDeactivatedCode, StringComparison.Ordinal) ||
           string.Equals(code, AgentRevokedCode, StringComparison.Ordinal);

    public static bool IsProtocolOrConfigCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return false;

        return code switch
        {
            "agent_protocol_mismatch" => true,
            "agent_config_mismatch" => true,
            "unsupported_schema_version" => true,
            "unsupported_protocol_version" => true,
            "agent_configuration_invalid" => true,
            _ => false,
        };
    }

    public static AgentLifecycleSnapshot Normalize(AgentLifecycleSnapshot snapshot)
    {
        var reasonCode = NormalizeCode(snapshot.ReasonCode);
        var requestId = NormalizeRequestId(snapshot.LastRequestId);
        var count = Math.Clamp(snapshot.GenericAuthFailureCount, 0, 2);
        var nextAttempt = snapshot.NextAttemptUtc?.ToUniversalTime();
        return snapshot with
        {
            ReasonCode = reasonCode,
            LastRequestId = requestId,
            NextAttemptUtc = nextAttempt,
            GenericAuthFailureCount = count,
            UpdatedAtUtc = snapshot.EffectiveUpdatedAtUtc.ToUniversalTime(),
        };
    }

    public static AgentLifecycleState ClassifyHttpFailure(
        AgentHttpFailureInfo failure,
        bool duringRefresh,
        bool manualOperation,
        int priorGenericAuthFailures)
    {
        if (IsTerminalCode(failure.Code))
            return AgentLifecycleState.Retired;

        if (IsProtocolOrConfigCode(failure.Code) ||
            failure.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Conflict)
        {
            return AgentLifecycleState.BlockedConfig;
        }

        if (IsTransientHttpStatus(failure.StatusCode))
            return AgentLifecycleState.Degraded;

        if (failure.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            // Refresh failures are intentionally conservative: a single
            // generic response never destroys credentials. An explicit manual
            // retry after a prior generic auth failure asks for re-enrollment.
            if (manualOperation && priorGenericAuthFailures >= 1)
                return AgentLifecycleState.NeedsReenrollment;
            return AgentLifecycleState.AuthSuspect;
        }

        return AgentLifecycleState.Active;
    }

    public static bool IsTransientHttpStatus(HttpStatusCode statusCode)
        => statusCode is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests ||
           (int)statusCode is >= 500 and <= 599;

    private static string? NormalizeCode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var normalized = value.Trim();
        if (normalized.Length > 64)
            return null;

        foreach (var ch in normalized)
        {
            if (!(char.IsAsciiLetterOrDigit(ch) || ch is '_' or '-' or '.' or ':'))
                return null;
        }

        return normalized;
    }

    private static string? NormalizeRequestId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var normalized = value.Trim();
        if (normalized.Length > 64)
            return null;

        foreach (var ch in normalized)
        {
            if (!(char.IsAsciiLetterOrDigit(ch) || ch is '_' or '-' or '.' or ':'))
                return null;
        }

        return normalized;
    }
}

public class AgentLifecycleDormantException : InvalidOperationException
{
    public AgentLifecycleDormantException(AgentLifecycleSnapshot snapshot)
        : base($"Agent automatic network is paused (state={snapshot.State}).")
    {
        State = snapshot.State;
        ReasonCode = snapshot.ReasonCode;
    }

    public AgentLifecycleState State { get; }
    public string? ReasonCode { get; }
}

public sealed class AgentRetiredException : AgentLifecycleDormantException
{
    public AgentRetiredException(AgentLifecycleSnapshot snapshot)
        : base(snapshot)
    {
    }
}

public static class AgentLifecycleStateStoreExtensions
{
    public static async Task<AgentLifecycleSnapshot> TransitionAsync(
        this IAgentLifecycleStateStore store,
        AgentLifecycleState state,
        string? reasonCode,
        string? requestId,
        DateTimeOffset? nextAttemptUtc,
        int? genericAuthFailureCount,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(store);
        var current = await store.LoadAsync(ct).ConfigureAwait(false);
        var next = new AgentLifecycleSnapshot(
            State: state,
            ReasonCode: reasonCode,
            LastRequestId: requestId,
            NextAttemptUtc: nextAttemptUtc,
            GenericAuthFailureCount: genericAuthFailureCount ?? current.GenericAuthFailureCount,
            UpdatedAtUtc: DateTimeOffset.UtcNow);
        next = AgentLifecycleStatePolicy.Normalize(next);
        await store.SaveAsync(next, ct).ConfigureAwait(false);
        return next;
    }
}

/// <summary>
/// Applies the lifecycle policy to bounded HTTP failures. Terminal state is
/// written before local credentials are cleared; generic failures only pause
/// traffic and preserve the DPAPI payload.
/// </summary>
public sealed class AgentLifecycleController
{
    private readonly IAgentLifecycleStateStore _store;
    private readonly ISecretStore? _secrets;
    private readonly IAgentLogger _log;

    public AgentLifecycleController(
        IAgentLifecycleStateStore store,
        ISecretStore? secrets = null,
        IAgentLogger? log = null)
    {
        _store = store;
        _secrets = secrets;
        _log = log ?? NullAgentLogger.Instance;
    }

    public Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct)
        => _store.LoadAsync(ct);

    public async Task<AgentLifecycleSnapshot> RecordHttpFailureAsync(
        AgentHttpFailureInfo failure,
        bool duringRefresh,
        bool manualOperation,
        CancellationToken ct)
    {
        var current = AgentLifecycleStatePolicy.Normalize(
            await _store.LoadAsync(ct).ConfigureAwait(false));
        var nextState = AgentLifecycleStatePolicy.ClassifyHttpFailure(
            failure,
            duringRefresh,
            manualOperation,
            current.GenericAuthFailureCount);

        // Retired is terminal. A late response from an in-flight request must
        // never make a retired agent active or degraded again.
        if (current.State == AgentLifecycleState.Retired)
            throw new AgentRetiredException(current);

        // A manual request made while a dormant state is already persisted may
        // observe a temporary outage, but that outage must not reopen automatic
        // traffic or replace the durable auth/config decision.
        if (nextState == AgentLifecycleState.Degraded &&
            !AgentLifecycleStates.AllowsAutomaticNetwork(current.State))
        {
            return current;
        }

        if (nextState == AgentLifecycleState.Active)
            return current;

        var authFailures = current.GenericAuthFailureCount;
        if (failure.StatusCode is System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden &&
            !AgentLifecycleStatePolicy.IsTerminalCode(failure.Code))
        {
            authFailures = Math.Min(2, authFailures + 1);
        }

        var next = new AgentLifecycleSnapshot(
            State: nextState,
            ReasonCode: failure.Code ?? ReasonForStatus(failure.StatusCode, nextState),
            LastRequestId: failure.RequestId ?? current.LastRequestId,
            NextAttemptUtc: null,
            GenericAuthFailureCount: authFailures,
            UpdatedAtUtc: DateTimeOffset.UtcNow);
        next = AgentLifecycleStatePolicy.Normalize(next);

        // Persist first so a crash between the state transition and secret
        // clear cannot restart the service with automatic network enabled.
        await _store.SaveAsync(next, ct).ConfigureAwait(false);
        if (nextState == AgentLifecycleState.Retired)
        {
            if (_secrets is not null)
                await _secrets.ClearAsync(ct).ConfigureAwait(false);
            _log.Warn($"Agent lifecycle retired by confirmed server code={next.ReasonCode}.");
            throw new AgentRetiredException(next);
        }

        return next;
    }

    public async Task<AgentLifecycleSnapshot> RecordTransientFailureAsync(
        string reasonCode,
        string? requestId,
        CancellationToken ct)
    {
        var current = AgentLifecycleStatePolicy.Normalize(
            await _store.LoadAsync(ct).ConfigureAwait(false));
        if (!AgentLifecycleStates.AllowsAutomaticNetwork(current.State))
            return current;

        var next = AgentLifecycleStatePolicy.Normalize(current with
        {
            State = AgentLifecycleState.Degraded,
            ReasonCode = reasonCode,
            LastRequestId = requestId ?? current.LastRequestId,
            NextAttemptUtc = null,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        });
        await _store.SaveAsync(next, ct).ConfigureAwait(false);
        return next;
    }

    public async Task<AgentLifecycleSnapshot> RecordTerminalResponseAsync(
        string code,
        string? requestId,
        CancellationToken ct)
    {
        var failure = new AgentHttpFailureInfo(
            HttpStatusCode.Unauthorized,
            TransportCode: null,
            DetailCode: code,
            Status: null,
            RequestId: requestId,
            RetryAfter: null);
        return await RecordHttpFailureAsync(
            failure,
            duringRefresh: false,
            manualOperation: false,
            ct).ConfigureAwait(false);
    }

    public async Task<AgentLifecycleSnapshot> RetireAsync(
        string code,
        string? requestId,
        CancellationToken ct)
    {
        if (!AgentLifecycleStatePolicy.IsTerminalCode(code))
            throw new ArgumentException("Only approved terminal lifecycle codes may retire an agent.", nameof(code));

        var current = AgentLifecycleStatePolicy.Normalize(
            await _store.LoadAsync(ct).ConfigureAwait(false));
        if (current.State == AgentLifecycleState.Retired &&
            string.Equals(current.ReasonCode, AgentLifecycleStatePolicy.AgentRevokedCode, StringComparison.Ordinal))
        {
            throw new AgentRetiredException(current);
        }

        var next = current with
        {
            State = AgentLifecycleState.Retired,
            ReasonCode = code,
            LastRequestId = requestId,
            NextAttemptUtc = null,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        };
        await _store.SaveAsync(AgentLifecycleStatePolicy.Normalize(next), ct).ConfigureAwait(false);
        if (_secrets is not null)
            await _secrets.ClearAsync(ct).ConfigureAwait(false);

        throw new AgentRetiredException(AgentLifecycleStatePolicy.Normalize(next));
    }

    public async Task<AgentLifecycleSnapshot> MarkActiveAsync(CancellationToken ct)
    {
        var current = AgentLifecycleStatePolicy.Normalize(
            await _store.LoadAsync(ct).ConfigureAwait(false));
        if (current.State == AgentLifecycleState.Retired &&
            !string.Equals(
                current.ReasonCode,
                AgentLifecycleStatePolicy.AgentDeactivatedCode,
                StringComparison.Ordinal))
        {
            throw new AgentRetiredException(current);
        }
        if (!AgentLifecycleStates.AllowsAutomaticNetwork(current.State))
        {
            // Explicit re-enrollment may recover a soft deactivation after new
            // credentials have been provisioned; all other dormant states stay
            // dormant until their dedicated operator action succeeds.
            if (current.State == AgentLifecycleState.Retired)
            {
                var reenrolled = AgentLifecycleStatePolicy.Normalize(current with
                {
                    State = AgentLifecycleState.Active,
                    ReasonCode = null,
                    LastRequestId = null,
                    NextAttemptUtc = null,
                    GenericAuthFailureCount = 0,
                    UpdatedAtUtc = DateTimeOffset.UtcNow,
                });
                await _store.SaveAsync(reenrolled, ct).ConfigureAwait(false);
                return reenrolled;
            }

            return current;
        }

        // Preserve bounded diagnostic metadata across recovery; only the
        // retry schedule and consecutive generic-auth count are cleared.
        var next = AgentLifecycleStatePolicy.Normalize(current with
        {
            State = AgentLifecycleState.Active,
            NextAttemptUtc = null,
            GenericAuthFailureCount = 0,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        });
        await _store.SaveAsync(next, ct).ConfigureAwait(false);
        return next;
    }

    public async Task<AgentLifecycleSnapshot> SetNextAttemptAsync(
        DateTimeOffset? nextAttemptUtc,
        CancellationToken ct)
    {
        var current = await _store.LoadAsync(ct).ConfigureAwait(false);
        var next = AgentLifecycleStatePolicy.Normalize(current with
        {
            NextAttemptUtc = nextAttemptUtc,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        });
        await _store.SaveAsync(next, ct).ConfigureAwait(false);
        return next;
    }

    public async Task EnsureAutomaticNetworkAllowedAsync(CancellationToken ct)
    {
        var snapshot = await _store.LoadAsync(ct).ConfigureAwait(false);
        if (!AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State))
            throw snapshot.State == AgentLifecycleState.Retired
                ? new AgentRetiredException(snapshot)
                : new AgentLifecycleDormantException(snapshot);
    }

    private static string ReasonForStatus(
        System.Net.HttpStatusCode status,
        AgentLifecycleState state)
        => state switch
        {
            AgentLifecycleState.Degraded => status switch
            {
                System.Net.HttpStatusCode.RequestTimeout => "request_timeout",
                System.Net.HttpStatusCode.TooManyRequests => "rate_limited",
                _ when (int)status is >= 500 and <= 599 => "server_unavailable",
                _ => "network_transient",
            },
            AgentLifecycleState.AuthSuspect => status is System.Net.HttpStatusCode.Forbidden
                ? "auth_forbidden"
                : "auth_unauthorized",
            AgentLifecycleState.BlockedConfig => status is System.Net.HttpStatusCode.Conflict
                ? "config_conflict"
                : "config_not_found",
            AgentLifecycleState.NeedsReenrollment => "auth_reenrollment_required",
            _ => "lifecycle_paused",
        };
}
