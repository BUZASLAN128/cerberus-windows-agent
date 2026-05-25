using Cerberus.Agent.Core;
using System.Diagnostics;

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

        if (!string.Equals(plan.ArtifactKind, "msi", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only MSI update artifacts are supported.");

        var updaterPath = ResolveUpdaterPath();
        if (!System.IO.File.Exists(updaterPath))
            throw new System.IO.FileNotFoundException("Agent updater executable not found.", updaterPath);

        Process.Start(new ProcessStartInfo
        {
            FileName = updaterPath,
            Arguments = $"\"{plan.ArtifactPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        _log.Warn($"Agent MSI updater launched: artifact={System.IO.Path.GetFileName(plan.ArtifactPath)}");
    }

    internal static string ResolveUpdaterPath()
    {
        var current = Environment.ProcessPath ?? AppContext.BaseDirectory;
        var dir = System.IO.File.Exists(current)
            ? System.IO.Path.GetDirectoryName(current)
            : current;
        return System.IO.Path.Combine(dir ?? AppContext.BaseDirectory, "Cerberus.Agent.Updater.exe");
    }
}
