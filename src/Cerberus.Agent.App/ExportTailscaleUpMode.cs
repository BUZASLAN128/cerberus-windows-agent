using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App;

internal static class ExportTailscaleUpMode
{
    public static async Task<int> RunAsync(CancellationToken ct)
    {
        using var log = AgentFileLogger.CreateDefault(alsoConsole: true);
        try
        {
            var path = await TailscaleUpExporter.ExportAsync(ct);
            if (path is null)
            {
                log.Error("Tailscale preauth info missing. Register the agent first.");
                return 2;
            }

            log.Info($"Wrote tailscale up command file: {path}");
            return 0;
        }
        catch (Exception ex)
        {
            log.Error("Export tailscale up failed.", ex);
            return 2;
        }
    }
}

