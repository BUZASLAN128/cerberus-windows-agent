using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App;

internal static partial class ServiceMode
{
    // Both compiled profiles enter the same cache lifecycle; snapshot collection only reads this cache.
    internal static IDisposable StartTelemetryBackgroundWork(IAgentLogger log, WindowsUpdateCache? cache = null)
    {
        cache ??= WindowsUpdateCache.Shared;
        cache.Start(log);
        return cache;
    }
}
