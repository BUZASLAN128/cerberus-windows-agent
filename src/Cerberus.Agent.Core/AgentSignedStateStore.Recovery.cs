namespace Cerberus.Agent.Core;

public sealed partial class AgentSignedStateStore
{
    private bool? _recoverySourceSupported;

    public bool RequiresRecovery
    {
        get { lock (_gate) { EnsureLoaded(); return _unreadable || _state?.Reset is not null; } }
    }

    public long RecoveryFloor
    {
        get
        {
            lock (_gate)
            {
                EnsureLoaded();
                var id = _currentAgentId ?? _state?.AgentId ?? _hwm?.AgentId;
                return id is null ? 0 : Load(id).StateSeq;
            }
        }
    }

    public void SetRecoverySourceSupported(bool supported)
    {
        lock (_gate) _recoverySourceSupported = supported;
    }

    public bool RecoveryControlOnly
    {
        get { lock (_gate) return RequiresRecovery && _recoverySourceSupported != false; }
    }

    public bool HoldsNormalWork()
    {
        lock (_gate)
        {
            EnsureLoaded();
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
