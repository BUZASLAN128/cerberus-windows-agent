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

        var runnerPath = PrepareUpdaterRunner(updaterPath, plan.ArtifactPath);
        LaunchUpdater(runnerPath, plan.ArtifactPath, requireElevation);
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

    internal static string PrepareUpdaterRunner(string updaterPath, string artifactPath)
    {
        var sourceDir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(updaterPath))
            ?? throw new InvalidOperationException("Agent updater directory could not be resolved.");
        var artifactDir = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(artifactPath))
            ?? throw new InvalidOperationException("Agent update artifact directory could not be resolved.");
        var runnerDir = System.IO.Path.Combine(
            artifactDir,
            $"updater-runner-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}");
        System.IO.Directory.CreateDirectory(runnerDir);

        foreach (var oldRunner in System.IO.Directory.EnumerateDirectories(artifactDir, "updater-runner-*"))
        {
            if (string.Equals(oldRunner, runnerDir, StringComparison.OrdinalIgnoreCase))
                continue;

            TryDeleteDirectory(oldRunner);
        }

        foreach (var file in System.IO.Directory.EnumerateFiles(sourceDir))
        {
            var extension = System.IO.Path.GetExtension(file);
            if (!IsRunnerFileExtension(extension))
                continue;

            var target = System.IO.Path.Combine(runnerDir, System.IO.Path.GetFileName(file));
            System.IO.File.Copy(file, target, overwrite: true);
        }

        var runnerPath = System.IO.Path.Combine(runnerDir, System.IO.Path.GetFileName(updaterPath));
        if (!System.IO.File.Exists(runnerPath))
            throw new System.IO.FileNotFoundException("Staged updater runner executable not found.", runnerPath);
        return runnerPath;
    }

    private static bool IsRunnerFileExtension(string? extension)
        => extension is not null &&
           (extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".config", StringComparison.OrdinalIgnoreCase));

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (System.IO.Directory.Exists(path))
                System.IO.Directory.Delete(path, recursive: true);
        }
        catch (Exception ex) when (ex is System.IO.IOException or UnauthorizedAccessException)
        {
        }
    }
}
