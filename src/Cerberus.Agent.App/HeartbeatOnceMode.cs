using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App;

internal static class HeartbeatOnceMode
{
    public static async Task<int> RunAsync(CancellationToken ct)
    {
        using var log = AgentFileLogger.CreateUser(alsoConsole: true);
        if (!Elevation.IsAdministrator())
        {
            var elevatedExitCode = await Elevation.RunElevatedAndWaitAsync("--heartbeat-once", ct).ConfigureAwait(false);
            log.Info(elevatedExitCode is null
                ? "Service recovery elevation was not completed."
                : $"Elevated service recovery exited with code {elevatedExitCode}.");
            return elevatedExitCode == 0 ? 0 : 2;
        }

        var result = await AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("retry"), ct).ConfigureAwait(false);
        log.Info($"Service recovery result: {result.Code}.");
        return result.Success ? 0 : 2;
    }
}
