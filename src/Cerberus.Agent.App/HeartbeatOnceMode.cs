using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App;

internal static class HeartbeatOnceMode
{
    public static async Task<int> RunAsync(CancellationToken ct)
    {
        using var log = AgentFileLogger.CreateUser(alsoConsole: true);
        var result = await AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("retry"), ct).ConfigureAwait(false);
        log.Info($"Service recovery result: {result.Code}.");
        return result.Success ? 0 : 2;
    }
}
