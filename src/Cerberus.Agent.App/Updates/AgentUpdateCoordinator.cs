using Cerberus.Agent.Core;
using System.Diagnostics;

namespace Cerberus.Agent.App.Updates;

internal sealed class AgentUpdateCoordinator : IAgentUpdateCoordinator
{
    private static readonly TimeSpan AutomaticLaunchCooldown = TimeSpan.FromMinutes(15);

    private readonly AgentUpdateStager _stager;
    private readonly IAgentLogger _log;
    private readonly AgentUpdateLaunchGate _automaticLaunchGate;
    private readonly AgentUpdateStateStore? _stateStore;

    public AgentUpdateCoordinator(AgentUpdateStager stager, IAgentLogger log)
        : this(stager, log, new AgentUpdateLaunchGate(AutomaticLaunchCooldown), stateStore: null)
    {
    }

    public AgentUpdateCoordinator(AgentUpdateStager stager, IAgentLogger log, AgentUpdateStateStore? stateStore)
        : this(stager, log, new AgentUpdateLaunchGate(AutomaticLaunchCooldown), stateStore)
    {
    }

    internal AgentUpdateCoordinator(
        AgentUpdateStager stager,
        IAgentLogger log,
        AgentUpdateLaunchGate automaticLaunchGate,
        AgentUpdateStateStore? stateStore = null)
    {
        _stager = stager;
        _log = log;
        _automaticLaunchGate = automaticLaunchGate;
        _stateStore = stateStore;
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
            if (!signal.Required)
            {
                await StageUpdateAsync(signal, campaignId: null, commandId: null, ct).ConfigureAwait(false);
                await WriteStateAsync(
                    AgentUpdateStates.Prompting,
                    ct,
                    targetVersion: check.Version,
                    channel: check.Channel,
                    manifestUrl: check.ManifestUrl,
                    artifactSha256: null).ConfigureAwait(false);
                return;
            }

            _log.Warn(
                $"Agent required update applying through service: version={check.Version ?? "-"}, channel={check.Channel ?? "-"}, reason={check.Reason ?? "-"}");
            await StageAndLaunchUpdateAsync(signal, requireElevation: false, ct).ConfigureAwait(false);
        }
        catch
        {
            _automaticLaunchGate.Clear(check);
            throw;
        }
    }

    public Task<AgentUpdateCheckResult> CheckUpdateAsync(HeartbeatResponse response, CancellationToken ct)
        => _stager.CheckAsync(response, ct);

    public Task<AgentUpdateCheckResult> CheckUpdateAsync(AgentUpdateSignal signal, CancellationToken ct)
        => _stager.CheckAsync(signal, ct);

    public async Task<AgentUpdatePlan?> StageUpdateAsync(
        HeartbeatResponse response,
        string? campaignId,
        string? commandId,
        CancellationToken ct)
    {
        var signal = AgentUpdateStager.FromHeartbeat(response);
        return await StageUpdateAsync(signal, campaignId, commandId, ct).ConfigureAwait(false);
    }

    public async Task<AgentUpdatePlan?> StageUpdateAsync(
        AgentUpdateSignal signal,
        string? campaignId,
        string? commandId,
        CancellationToken ct)
    {
        await WriteStateAsync(
            AgentUpdateStates.Downloading,
            ct,
            channel: signal.Channel,
            manifestUrl: signal.ManifestUrl,
            campaignId: campaignId,
            commandId: commandId).ConfigureAwait(false);

        try
        {
            var plan = await _stager.StageAsync(signal, ct).ConfigureAwait(false);
            if (plan is null)
            {
                await WriteStateAsync(
                    AgentUpdateStates.Current,
                    ct,
                    channel: signal.Channel,
                    manifestUrl: signal.ManifestUrl,
                    campaignId: campaignId,
                    commandId: commandId,
                    markChecked: true).ConfigureAwait(false);
                return null;
            }

            await WriteStateAsync(
                AgentUpdateStates.Staged,
                ct,
                targetVersion: plan.Version,
                channel: plan.Channel,
                manifestUrl: signal.ManifestUrl,
                campaignId: campaignId,
                commandId: commandId,
                artifactSha256: plan.Sha256).ConfigureAwait(false);
            return plan;
        }
        catch (Exception ex)
        {
            await WriteStateAsync(
                AgentUpdateStates.Failed,
                ct,
                channel: signal.Channel,
                manifestUrl: signal.ManifestUrl,
                campaignId: campaignId,
                commandId: commandId,
                errorCode: AgentUpdateErrorCodes.Classify(ex),
                errorMessage: ex.Message).ConfigureAwait(false);
            throw;
        }
    }

    public async Task<bool> StageAndLaunchUpdateAsync(
        HeartbeatResponse response,
        bool requireElevation,
        CancellationToken ct)
    {
        var signal = AgentUpdateStager.FromHeartbeat(response);
        return await StageAndLaunchUpdateAsync(signal, requireElevation, ct).ConfigureAwait(false);
    }

    public async Task<bool> StageAndLaunchUpdateAsync(
        AgentUpdateSignal signal,
        bool requireElevation,
        CancellationToken ct)
    {
        var plan = await StageUpdateAsync(signal, campaignId: null, commandId: null, ct).ConfigureAwait(false);
        if (plan is null)
            return false;

        await WriteStateAsync(
            AgentUpdateStates.Applying,
            ct,
            targetVersion: plan.Version,
            channel: plan.Channel,
            manifestUrl: signal.ManifestUrl,
            artifactSha256: plan.Sha256).ConfigureAwait(false);

        try
        {
            var launched = StageAndLaunchUpdate(plan, requireElevation);
            if (launched)
            {
                await WriteStateAsync(
                    AgentUpdateStates.InstallerStarted,
                    ct,
                    targetVersion: plan.Version,
                    channel: plan.Channel,
                    manifestUrl: signal.ManifestUrl,
                    artifactSha256: plan.Sha256).ConfigureAwait(false);
            }
            return launched;
        }
        catch (Exception ex)
        {
            await WriteStateAsync(
                AgentUpdateStates.Failed,
                ct,
                targetVersion: plan.Version,
                channel: plan.Channel,
                manifestUrl: signal.ManifestUrl,
                artifactSha256: plan.Sha256,
                errorCode: AgentUpdateErrorCodes.Classify(ex),
                errorMessage: ex.Message).ConfigureAwait(false);
            throw;
        }
    }

    private bool StageAndLaunchUpdate(AgentUpdatePlan? plan, bool requireElevation)
    {
        if (plan is null)
            return false;

        if (!AgentUpdateSecurity.IsLocalSystem())
            throw new InvalidOperationException("Only the installed agent service may launch the updater.");
        if (string.IsNullOrWhiteSpace(plan.AttemptId) || !AgentUpdateSecurity.IsSafeAttemptId(plan.AttemptId))
            throw new InvalidOperationException("Update attempt identifier is invalid.");

        _log.Warn(
            $"Agent update staged: version={plan.Version}, channel={plan.Channel}, reason={plan.Reason}");

        if (!string.Equals(plan.ArtifactKind, "msi", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only MSI update artifacts are supported.");

        var updaterPath = ResolveUpdaterPath();
        if (!System.IO.File.Exists(updaterPath))
            throw new System.IO.FileNotFoundException("Agent updater executable not found.", updaterPath);

        LaunchUpdater(updaterPath, plan.AttemptId);
        _log.Warn($"Agent MSI updater launched: attempt={plan.AttemptId}");
        return true;
    }

    private static void LaunchUpdater(string updaterPath, string attemptId)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = updaterPath,
            ArgumentList = { "--attempt", attemptId },
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        Process.Start(startInfo)?.Dispose();
    }

    internal static string ResolveUpdaterPath()
    {
        var current = Environment.ProcessPath ?? AppContext.BaseDirectory;
        var currentDir = System.IO.File.Exists(current)
            ? System.IO.Path.GetDirectoryName(current)
            : current;
        var registryRoot = ReadRegistryString("runtimeRoot");
        var installRoot = ReadRegistryString("installRoot");
        var dir = !string.IsNullOrWhiteSpace(registryRoot)
            ? registryRoot
            : !string.IsNullOrWhiteSpace(installRoot)
                ? System.IO.Path.Combine(installRoot, "app")
                : currentDir;
        if (string.IsNullOrWhiteSpace(dir))
            throw new InvalidOperationException("Canonical agent runtime root is not registered.");

        var fullDir = System.IO.Path.GetFullPath(dir.Trim());
        AgentUpdateSecurity.ValidateTrustedPath(
            fullDir,
            System.IO.Path.GetPathRoot(fullDir) ?? fullDir,
            allowMissing: false);
        var path = System.IO.Path.Combine(fullDir, "Cerberus.Agent.Updater.exe");
        AgentUpdateSecurity.ValidateTrustedPath(path, fullDir, allowMissing: false);
        if (!System.IO.File.Exists(path))
            throw new System.IO.FileNotFoundException("Agent updater executable is not installed.");
        return path;
    }

    private static string? ReadRegistryString(string valueName)
    {
        if (!OperatingSystem.IsWindows())
            return null;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Cerberus\WindowsAgent", writable: false);
            return key?.GetValue(valueName)?.ToString();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
        {
            return null;
        }
    }

    private Task WriteStateAsync(
        string state,
        CancellationToken ct,
        string? targetVersion = null,
        string? channel = null,
        string? manifestUrl = null,
        string? campaignId = null,
        string? commandId = null,
        string? artifactSha256 = null,
        string? errorCode = null,
        string? errorMessage = null,
        bool markChecked = false)
    {
        return _stateStore is null
            ? Task.CompletedTask
            : _stateStore.TryWriteTransitionAsync(
                state,
                WindowsDeviceInfo.GetAgentVersion(),
                ct,
                targetVersion: targetVersion,
                channel: channel,
                manifestUrl: manifestUrl,
                campaignId: campaignId,
                commandId: commandId,
                artifactSha256: artifactSha256,
                errorCode: errorCode,
                errorMessage: errorMessage,
                markChecked: markChecked);
    }
}
