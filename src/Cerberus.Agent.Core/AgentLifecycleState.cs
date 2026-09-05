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
    public long Generation { get; init; }
    public long Revision { get; init; }
    public bool QuiescenceComplete { get; init; } = true;
    public int TransientFailureCount { get; init; }
    public string? LastEnrollmentNonce { get; init; }
}

public interface IAgentLifecycleStateStore
{
    Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct);
    Task SaveAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct);
    Task<AgentLifecycleSnapshot?> TrySaveAsync(AgentLifecycleSnapshot snapshot, long expectedRevision, CancellationToken ct);
    Task<bool> ExecuteIfCurrentAsync(long expectedGeneration, Func<CancellationToken, Task> action, CancellationToken ct);
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
        if (await TrySaveAsync(snapshot, snapshot.Revision, ct).ConfigureAwait(false) is null)
            throw new InvalidOperationException("Lifecycle generation changed.");
    }

    public async Task<AgentLifecycleSnapshot?> TrySaveAsync(AgentLifecycleSnapshot snapshot, long expectedRevision, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_snapshot.Revision != expectedRevision)
                return null;
            _snapshot = AgentLifecycleStatePolicy.ForCommit(_snapshot, snapshot);
            return _snapshot;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> ExecuteIfCurrentAsync(long expectedGeneration, Func<CancellationToken, Task> action, CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_snapshot.Generation != expectedGeneration)
                return false;
            await action(ct).ConfigureAwait(false);
            return true;
        }
        finally { _gate.Release(); }
    }
}

public static class AgentLifecycleStatePolicy
{
    public static AgentLifecycleSnapshot ForCommit(AgentLifecycleSnapshot current, AgentLifecycleSnapshot next)
    {
        var boundaryChanged = current.State != next.State &&
            (AgentLifecycleStates.IsDormant(current.State) || AgentLifecycleStates.IsDormant(next.State));
        return Normalize(next with
        {
            Revision = checked(current.Revision + 1),
            Generation = next.Generation > current.Generation ? checked(current.Generation + 1) :
                boundaryChanged ? checked(current.Generation + 1) : current.Generation,
        });
    }

    public const string AgentDeactivatedCode = "agent_deactivated";
    public const string AgentRevokedCode = "agent_revoked";
    public const string AgentReenrollRequiredCode = "agent_reenroll_required";

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
            TransientFailureCount = Math.Clamp(snapshot.TransientFailureCount, 0, 30),
            UpdatedAtUtc = snapshot.EffectiveUpdatedAtUtc.ToUniversalTime(),
        };
    }

    public static AgentLifecycleState ClassifyHttpFailure(
        AgentHttpFailureInfo failure,
        bool duringRefresh,
        bool manualOperation,
        int priorGenericAuthFailures)
    {
        if (failure.StatusCode == HttpStatusCode.Unauthorized && IsTerminalCode(failure.Code))
            return AgentLifecycleState.Retired;

        if (failure.StatusCode == HttpStatusCode.Unauthorized && failure.Code == AgentReenrollRequiredCode)
            return AgentLifecycleState.NeedsReenrollment;

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
        CancellationToken ct,
        long? expectedGeneration = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        var current = await store.LoadAsync(ct).ConfigureAwait(false);
        if (expectedGeneration is not null && current.Generation != expectedGeneration)
            return current;
        if (current.State == AgentLifecycleState.Retired ||
            (AgentLifecycleStates.IsDormant(current.State) && AgentLifecycleStates.AllowsAutomaticNetwork(state)))
            return current;
        var next = current with
        {
            State = state,
            ReasonCode = reasonCode,
            LastRequestId = requestId,
            NextAttemptUtc = nextAttemptUtc,
            GenericAuthFailureCount = genericAuthFailureCount ?? current.GenericAuthFailureCount,
            QuiescenceComplete = AgentLifecycleStates.IsDormant(state) ? false : current.QuiescenceComplete,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        };
        next = AgentLifecycleStatePolicy.Normalize(next);
        return await store.TrySaveAsync(next, current.Revision, ct).ConfigureAwait(false)
            ?? await store.LoadAsync(ct).ConfigureAwait(false);
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
    private readonly Func<CancellationToken, Task>? _quiesce;

    public AgentLifecycleController(
        IAgentLifecycleStateStore store,
        ISecretStore? secrets = null,
        IAgentLogger? log = null,
        Func<CancellationToken, Task>? quiesce = null)
    {
        _store = store;
        _secrets = secrets;
        _log = log ?? NullAgentLogger.Instance;
        _quiesce = quiesce;
    }

    public Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct)
        => _store.LoadAsync(ct);

    public Task<AgentLifecycleSnapshot> RecordHttpFailureAsync(
        AgentHttpFailureInfo failure,
        bool duringRefresh,
        bool manualOperation,
        CancellationToken ct,
        long? expectedGeneration = null,
        bool authenticatedControlPlane = false)
        => RecordHttpFailureCoreAsync(failure, duringRefresh, manualOperation, ct, expectedGeneration, authenticatedControlPlane, 8);

    private async Task<AgentLifecycleSnapshot> RecordHttpFailureCoreAsync(AgentHttpFailureInfo failure,
        bool duringRefresh, bool manualOperation, CancellationToken ct, long? expectedGeneration,
        bool authenticatedControlPlane, int remainingCasAttempts)
    {
        var current = AgentLifecycleStatePolicy.Normalize(
            await _store.LoadAsync(ct).ConfigureAwait(false));
        if (expectedGeneration is not null && expectedGeneration != current.Generation)
            return current;
        if ((!authenticatedControlPlane || failure.StatusCode != HttpStatusCode.Unauthorized) &&
            (AgentLifecycleStatePolicy.IsTerminalCode(failure.Code) || failure.Code == AgentLifecycleStatePolicy.AgentReenrollRequiredCode))
            failure = failure with { DetailCode = null, TransportCode = null };
        var nextState = AgentLifecycleStatePolicy.ClassifyHttpFailure(
            failure,
            duringRefresh,
            manualOperation,
            current.GenericAuthFailureCount);

        // Retired is terminal. A late response from an in-flight request must
        // never make a retired agent active or degraded again.
        if (current.State == AgentLifecycleState.Retired)
            throw new AgentRetiredException(current);
        if (AgentLifecycleStates.IsDormant(current.State) && !manualOperation && nextState != AgentLifecycleState.Retired)
            return current;

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
        if (manualOperation && failure.StatusCode is System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.Forbidden &&
            !AgentLifecycleStatePolicy.IsTerminalCode(failure.Code) && failure.Code != AgentLifecycleStatePolicy.AgentReenrollRequiredCode)
        {
            authFailures = Math.Min(2, authFailures + 1);
        }

        var next = current with
        {
            State = nextState,
            ReasonCode = failure.Code ?? ReasonForStatus(failure.StatusCode, nextState),
            LastRequestId = failure.RequestId ?? current.LastRequestId,
            NextAttemptUtc = current.NextAttemptUtc,
            GenericAuthFailureCount = authFailures,
            QuiescenceComplete = AgentLifecycleStates.IsDormant(nextState) ? false : current.QuiescenceComplete,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        };
        next = AgentLifecycleStatePolicy.Normalize(next);

        // Persist first so a crash between the state transition and secret
        // clear cannot restart the service with automatic network enabled.
        var saved = await _store.TrySaveAsync(next, current.Revision, ct).ConfigureAwait(false);
        if (saved is null)
        {
            if (remainingCasAttempts <= 0)
                throw new InvalidOperationException("Lifecycle deny could not be committed.");
            return await RecordHttpFailureCoreAsync(failure, duringRefresh, manualOperation, ct,
                expectedGeneration, authenticatedControlPlane, remainingCasAttempts - 1).ConfigureAwait(false);
        }
        next = await CompletePendingQuiescenceAsync(ct).ConfigureAwait(false);
        if (nextState == AgentLifecycleState.Retired)
        {
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
        return await _store.TrySaveAsync(next, current.Revision, ct).ConfigureAwait(false)
            ?? await _store.LoadAsync(ct).ConfigureAwait(false);
    }

    public async Task<AgentLifecycleSnapshot> RecordTerminalResponseAsync(
        string code,
        string? requestId,
        CancellationToken ct,
        long? expectedGeneration = null)
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
            ct,
            expectedGeneration: expectedGeneration,
            authenticatedControlPlane: true).ConfigureAwait(false);
    }

    public async Task<AgentLifecycleSnapshot> RetireAsync(
        string code,
        string? requestId,
        CancellationToken ct)
    {
        if (!AgentLifecycleStatePolicy.IsTerminalCode(code))
            throw new ArgumentException("Only approved terminal lifecycle codes may retire an agent.", nameof(code));

        return await RecordTerminalResponseAsync(code, requestId, ct).ConfigureAwait(false);
    }

    public async Task<AgentLifecycleSnapshot> MarkActiveAsync(CancellationToken ct, long? expectedGeneration = null)
    {
        var current = AgentLifecycleStatePolicy.Normalize(
            await _store.LoadAsync(ct).ConfigureAwait(false));
        if (expectedGeneration is not null && expectedGeneration != current.Generation)
            throw new AgentLifecycleDormantException(current);
        if (
            !AgentLifecycleStates.AllowsAutomaticNetwork(current.State) || !current.QuiescenceComplete)
            return current;

        // Preserve bounded diagnostic metadata across recovery; only the
        // retry schedule and consecutive generic-auth count are cleared.
        var next = AgentLifecycleStatePolicy.Normalize(current with
        {
            State = AgentLifecycleState.Active,
            NextAttemptUtc = null,
            GenericAuthFailureCount = 0,
            TransientFailureCount = 0,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        });
        if (next == current)
            return current;
        var saved = await _store.TrySaveAsync(next, current.Revision, ct).ConfigureAwait(false);
        if (saved is null && expectedGeneration is not null)
            throw new AgentLifecycleDormantException(await _store.LoadAsync(ct).ConfigureAwait(false));
        return saved ?? await _store.LoadAsync(ct).ConfigureAwait(false);
    }

    public async Task<AgentLifecycleSnapshot> SetNextAttemptAsync(
        DateTimeOffset? nextAttemptUtc,
        CancellationToken ct)
    {
        var current = await _store.LoadAsync(ct).ConfigureAwait(false);
        if (AgentLifecycleStates.IsDormant(current.State))
            return current;
        var next = AgentLifecycleStatePolicy.Normalize(current with
        {
            NextAttemptUtc = nextAttemptUtc,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        });
        return await _store.TrySaveAsync(next, current.Revision, ct).ConfigureAwait(false)
            ?? await _store.LoadAsync(ct).ConfigureAwait(false);
    }

    public async Task EnsureAutomaticNetworkAllowedAsync(CancellationToken ct)
    {
        var snapshot = await _store.LoadAsync(ct).ConfigureAwait(false);
        if (!AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State) || !snapshot.QuiescenceComplete)
            throw snapshot.State == AgentLifecycleState.Retired
                ? new AgentRetiredException(snapshot)
                : new AgentLifecycleDormantException(snapshot);
    }

    /// <summary>Local-only cleanup after a durable deny, including crash recovery. No cleanup callback means pending, never completed.</summary>
    public async Task<AgentLifecycleSnapshot> CompletePendingQuiescenceAsync(CancellationToken ct)
    {
        var current = await _store.LoadAsync(ct).ConfigureAwait(false);
        if (current.QuiescenceComplete || AgentLifecycleStates.AllowsAutomaticNetwork(current.State) || _quiesce is null)
            return current;
        await _quiesce(ct).ConfigureAwait(false);
        // Only retire clears credentials; reenrollment-required preserves them.
        if (current.State == AgentLifecycleState.Retired && _secrets is not null)
        {
            if (!await _store.ExecuteIfCurrentAsync(current.Generation, _secrets.ClearAsync, ct).ConfigureAwait(false))
                return await _store.LoadAsync(ct).ConfigureAwait(false);
        }
        return await _store.TrySaveAsync(current with
        {
            QuiescenceComplete = true,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        }, current.Revision, ct).ConfigureAwait(false) ?? await _store.LoadAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Called only by the service after an explicit authenticated recovery attempt succeeds.</summary>
    public async Task<AgentLifecycleSnapshot> CompleteManualRecoveryAsync(long expectedGeneration, CancellationToken ct)
    {
        var current = await _store.LoadAsync(ct).ConfigureAwait(false);
        if (current.Generation != expectedGeneration || !current.QuiescenceComplete ||
            current.State is AgentLifecycleState.Retired or AgentLifecycleState.NeedsReenrollment)
            return current;
        return await _store.TrySaveAsync(current with
        {
            State = AgentLifecycleState.Active,
            ReasonCode = null,
            NextAttemptUtc = null,
            GenericAuthFailureCount = 0,
            TransientFailureCount = 0,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        }, current.Revision, ct).ConfigureAwait(false) ?? await _store.LoadAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Service-only completion after the protected promotion marker and backend identity have been verified.</summary>
    public async Task<AgentLifecycleSnapshot> CompleteEnrollmentAsync(long expectedGeneration, string nonce, CancellationToken ct)
    {
        if (!Guid.TryParseExact(nonce, "N", out _))
            throw new ArgumentException("Invalid enrollment nonce.", nameof(nonce));
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var current = await _store.LoadAsync(ct).ConfigureAwait(false);
            if (current.Generation != expectedGeneration || !current.QuiescenceComplete ||
                current.ReasonCode == AgentLifecycleStatePolicy.AgentRevokedCode || current.LastEnrollmentNonce == nonce)
                throw new AgentLifecycleDormantException(current);
            var next = current with
            {
                State = AgentLifecycleState.Active,
                Generation = checked(current.Generation + 1),
                ReasonCode = null,
                NextAttemptUtc = null,
                GenericAuthFailureCount = 0,
                TransientFailureCount = 0,
                LastEnrollmentNonce = nonce,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
            };
            var saved = await _store.TrySaveAsync(next, current.Revision, ct).ConfigureAwait(false);
            if (saved is not null) return saved;
        }
        throw new InvalidOperationException("Enrollment lifecycle changed concurrently.");
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
