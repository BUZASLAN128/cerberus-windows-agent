using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal sealed class AgentUpdateCoordinator : IAgentUpdateCoordinator
{
    private readonly AgentUpdateStager _stager;
    private readonly IAgentLogger _log;

    public AgentUpdateCoordinator(AgentUpdateStager stager, IAgentLogger log)
    {
        _stager = stager;
        _log = log;
    }

    public async Task HandleUpdateAsync(HeartbeatResponse response, CancellationToken ct)
    {
        var signal = AgentUpdateStager.FromHeartbeat(response);
        if (!signal.Required && !signal.Recommended)
            return;

        var plan = await _stager.StageAsync(response, ct).ConfigureAwait(false);
        if (plan is null)
            return;

        _log.Warn(
            $"Agent update staged: version={plan.Version}, channel={plan.Channel}, reason={plan.Reason}");
    }
}
