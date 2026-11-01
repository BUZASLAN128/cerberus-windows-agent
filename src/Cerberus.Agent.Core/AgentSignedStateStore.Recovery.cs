namespace Cerberus.Agent.Core;

public sealed partial class AgentSignedStateStore
{
    private bool? _recoverySourceSupported;
    private Func<(bool Pending, long Floor)>? _controlRecovery;

    internal void ConnectControlRecovery(Func<(bool Pending, long Floor)> recovery)
    { lock (_gate) _controlRecovery = recovery; }

    internal bool HasPendingControl
    { get { lock (_gate) return ControlRecovery().Pending; } }

    /// <summary>A replay high-water mark alone is not proof that the signed snapshot reached disk.</summary>
    internal bool HasPersistedState(string agentId, long sequence, bool exactSequence, string? commandId = null,
        AgentRevokeRegistration? revokeRegistration = null)
    {
        lock (_gate)
        {
            EnsureLoaded();
            if (sequence <= 0 || _unreadable || _state is not { Reset: null } stored ||
                stored.AgentId != agentId || stored.StateSeq < sequence || stored.StateSeq < HighWaterFor(agentId))
                return false;
            // A later state command may replace the last-applied id, but the same write retains
            // the revoke's own durable id and registration until its confirmed result is final.
            return ((!exactSequence || stored.StateSeq == sequence) &&
                    (commandId is null || stored.LastAppliedCommandId == commandId)) ||
                (commandId is not null && revokeRegistration is not null &&
                    stored.PendingRevoke is { } pending && pending.CommandId == commandId &&
                    pending.Registration == revokeRegistration);
        }
    }

    private (bool Pending, long Floor) ControlRecovery()
    {
        try { return _controlRecovery?.Invoke() ?? (false, 0); }
        catch { return (true, 0); }
    }

    internal bool RequiresSnapshotRecovery
    {
        get { lock (_gate) { EnsureLoaded(); return _unreadable || _state?.Reset is not null; } }
    }

    public bool RequiresRecovery
    { get { lock (_gate) return RequiresSnapshotRecovery || ControlRecovery().Pending; } }

    /// <summary>Read-only launch barrier for the current protected registration; never repairs storage.</summary>
    public bool HasPendingRevokeOrRecovery(AgentRevokeRegistration current)
    {
        lock (_gate)
        {
            try
            {
                var highWater = _highWater.Read(out var highWaterUnreadable);
                if (highWaterUnreadable) return true;
                var acceptedState = highWater is { Seq: > 0 } priorState && priorState.AgentId == current.AgentId;
                _file.ValidateDirectory();
                if (!_file.Exists()) return acceptedState;
                _file.ValidateFile();
                if (!TryRead(out var state) || state is null) return true;
                if (acceptedState && state.Reset is not null) return true;
                if (state.AgentId != current.AgentId && state.AgentId != AgentSignedState.UnknownAgentId) return false;
                // Update authorization uses positive control evidence. Runtime snapshot recovery
                // keeps its independent fail-closed policy in RequiresRecovery/HoldsNormalWork.
                if (state.PendingRevoke is not { } pending) return false;
                if (pending.Registration is not { } prior) return true;
                if (prior.TenantId is not null && current.TenantId is not null && prior.TenantId != current.TenantId) return false;
                return prior.EnrollmentNonce == current.EnrollmentNonce || current.EnrollmentNonce is null;
            }
            catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex)) { return true; }
        }
    }

    public long RecoveryFloor
    {
        get
        {
            lock (_gate)
            {
                EnsureLoaded();
                var id = _currentAgentId ?? _state?.AgentId ?? _hwm?.AgentId;
                return Math.Max(id is null ? 0 : Load(id).StateSeq, ControlRecovery().Floor);
            }
        }
    }

    public void SetRecoverySourceSupported(bool supported)
    {
        lock (_gate) _recoverySourceSupported = supported;
    }

    public bool RecoveryControlOnly
    {
        get { lock (_gate) return HasPendingControl || RequiresRecovery && _recoverySourceSupported != false; }
    }

    public bool HoldsNormalWork()
    {
        lock (_gate)
        {
            EnsureLoaded();
            if (HasPendingControl) return true;
            // A profile without signed state keeps its ordinary service path.
            // The signed-command queue still uses IsQuarantined and remains closed.
            if (RequiresRecovery && _recoverySourceSupported == false && _state?.PendingRevoke is null)
                return false;
            return IsQuarantined();
        }
    }

    private void EnterReset(string agentId)
    {
        _state = new AgentSignedState(agentId, HighWaterFor(agentId), true, null,
            Reset: AgentSignedState.ResetUnreadable);
        _unreadable = !TryPersist(_state);
    }
}
