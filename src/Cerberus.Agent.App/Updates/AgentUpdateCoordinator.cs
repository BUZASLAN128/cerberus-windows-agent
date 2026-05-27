using Cerberus.Agent.Core;
using System.Diagnostics;
using System.ComponentModel;

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

        await StageAndLaunchUpdateAsync(response, requireElevation: false, ct).ConfigureAwait(false);
    }

    public Task<AgentUpdateCheckResult> CheckUpdateAsync(HeartbeatResponse response, CancellationToken ct)
        => _stager.CheckAsync(response, ct);

    public async Task StageAndLaunchUpdateAsync(
        HeartbeatResponse response,
        bool requireElevation,
        CancellationToken ct)
    {
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

        LaunchUpdater(updaterPath, plan.ArtifactPath, requireElevation);
        _log.Warn($"Agent MSI updater launched: artifact={System.IO.Path.GetFileName(plan.ArtifactPath)}");
    }

    private static void LaunchUpdater(string updaterPath, string artifactPath, bool requireElevation)
    {
        var arguments = $"\"{artifactPath}\"";
        var startInfo = new ProcessStartInfo
        {
            FileName = updaterPath,
            Arguments = arguments,
            UseShellExecute = requireElevation,
            CreateNoWindow = !requireElevation,
        };

        if (requireElevation && !Elevation.IsAdministrator())
            startInfo.Verb = "runas";

        try
        {
            Process.Start(startInfo);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new InvalidOperationException("Update installation was canceled.", ex);
        }
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
