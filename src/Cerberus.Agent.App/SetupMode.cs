using Cerberus.Agent.App.Actions;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App;

internal static class SetupMode
{
    public static async Task<int> RunAsync(CancellationToken ct)
    {
        using var log = AgentFileLogger.CreateDefault(alsoConsole: true);
        try
        {
            var cfg = UiConfigStore.LoadMergedWithEnv();
            var result = await new AgentSetupFlow()
                .RunAsync(cfg, log, progress: log.Info, ct)
                .ConfigureAwait(false);
            log.Info(result.Message);
            return 0;
        }
        catch (Exception ex)
        {
            log.Error("Setup failed.", ex);
            return 2;
        }
    }
}
