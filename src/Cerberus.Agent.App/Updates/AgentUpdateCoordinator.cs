using Cerberus.Agent.Core;
using System.Diagnostics;
using System.ComponentModel;

namespace Cerberus.Agent.App.Updates;

internal sealed class AgentUpdateCoordinator : IAgentUpdateCoordinator
{
    private static readonly TimeSpan AutomaticLaunchCooldown = TimeSpan.FromMinutes(15);

    private readonly AgentUpdateStager _stager;
    private readonly IAgentLogger _log;
    private readonly AgentUpdateLaunchGate _automaticLaunchGate;

    public AgentUpdateCoordinator(AgentUpdateStager stager, IAgentLogger log)
        : this(stager, log, new AgentUpdateLaunchGate(AutomaticLaunchCooldown))
    {
    }

    internal AgentUpdateCoordinator(
        AgentUpdateStager stager,
        IAgentLogger log,
        AgentUpdateLaunchGate automaticLaunchGate)
    {
        _stager = stager;
        _log = log;
        _automaticLaunchGate = automaticLaunchGate;
    }

    public async Task HandleUpdateAsync(HeartbeatResponse response, CancellationToken ct)
    {
        var signal = AgentUpdateStager.FromHeartbeat(response);
        if (!signal.Required && !signal.Recommended)
            return;

        var check = await _stager.CheckAsync(response, ct).ConfigureAwait(false);
        if (!check.Available)
            return;

        if (!_automaticLaunchGate.TryBegin(check, DateTimeOffset.UtcNow))
        {
            _log.Warn(
                $"Agent automatic update launch suppressed: version={check.Version ?? "-"}, channel={check.Channel ?? "-"}, reason={check.Reason ?? "-"}");
            return;
        }

        try
        {
            _log.Warn(
                $"Agent automatic update accepted: version={check.Version ?? "-"}, channel={check.Channel ?? "-"}, reason={check.Reason ?? "-"}");
            await StageAndLaunchUpdateAsync(response, requireElevation: false, ct).ConfigureAwait(false);
        }
        catch
        {
            _automaticLaunchGate.Clear(check);
            throw;
        }
    }

    public Task<AgentUpdateCheckResult> CheckUpdateAsync(HeartbeatResponse response, CancellationToken ct)
        => _stager.CheckAsync(response, ct);

    public async Task<bool> StageAndLaunchUpdateAsync(
        HeartbeatResponse response,
        bool requireElevation,
        CancellationToken ct)
    {
        var plan = await _stager.StageAsync(response, ct).ConfigureAwait(false);
        if (plan is null)
            return false;

        _log.Warn(
            $"Agent update staged: version={plan.Version}, channel={plan.Channel}, reason={plan.Reason}");

        if (!string.Equals(plan.ArtifactKind, "msi", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only MSI update artifacts are supported.");

        var updaterPath = ResolveUpdaterPath();
        if (!System.IO.File.Exists(updaterPath))
            throw new System.IO.FileNotFoundException("Agent updater executable not found.", updaterPath);

        LaunchUpdater(updaterPath, plan.ArtifactPath, requireElevation);
        _log.Warn($"Agent MSI updater launched: artifact={System.IO.Path.GetFileName(plan.ArtifactPath)}");
        return true;
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
