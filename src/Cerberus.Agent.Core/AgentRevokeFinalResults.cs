using System.Collections.Concurrent;

namespace Cerberus.Agent.Core;

/// <summary>
/// Process-lifetime record of revoke results whose DONE result reached a final outcome in this process.
/// It survives worker restarts inside the process, so a revoke whose replay record could not be written
/// or read is still retried instead of leaving the network running under the revoked registration.
/// </summary>
public sealed class AgentRevokeFinalResults
{
    private readonly ConcurrentDictionary<(string AgentId, string CommandId), byte> _final = new();

    public void Mark(string agentId, string commandId) => _final[(agentId, commandId)] = 0;

    public bool Contains(string agentId, string commandId) => _final.ContainsKey((agentId, commandId));
}
