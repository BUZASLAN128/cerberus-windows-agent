using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

/// <summary>Heartbeat/command adapter. Durable policy, download and installation are owned by the local service engine.</summary>
internal sealed class AgentUpdateCoordinator : IAgentUpdateCoordinator
{
    public AgentUpdateCoordinator(AgentUpdateStager stager, IAgentLogger log) { }
    public AgentUpdateCoordinator(AgentUpdateStager stager, IAgentLogger log, AgentUpdateStateStore? stateStore) { }
    internal AgentUpdateCoordinator(AgentUpdateStager stager, IAgentLogger log, AgentUpdateLaunchGate automaticLaunchGate, AgentUpdateStateStore? stateStore = null) { }

    public Task HandleUpdateAsync(HeartbeatResponse response, CancellationToken ct)
        => AgentUpdateLocalService.HandleHeartbeatAsync(AgentUpdateStager.FromHeartbeat(response), ct);

    public Task<AgentUpdatePlan?> StageUpdateAsync(AgentUpdateSignal signal, string? campaignId, string? commandId, CancellationToken ct)
        => AgentUpdateLocalService.CheckAndStageAsync(automatic: true, required: signal.Required, ct);

    public Task<AgentUpdatePlan?> StageUpdateAsync(HeartbeatResponse response, string? campaignId, string? commandId, CancellationToken ct)
        => StageUpdateAsync(AgentUpdateStager.FromHeartbeat(response), campaignId, commandId, ct);

    public Task<AgentUpdateCheckResult> CheckUpdateAsync(HeartbeatResponse response, CancellationToken ct)
        => CheckUpdateAsync(AgentUpdateStager.FromHeartbeat(response), ct);

    public Task<AgentUpdateCheckResult> CheckUpdateAsync(AgentUpdateSignal signal, CancellationToken ct)
        => AgentUpdateLocalService.CheckOnlyAsync(automatic: true, ct);

    public Task<bool> StageAndLaunchUpdateAsync(HeartbeatResponse response, bool requireElevation, CancellationToken ct)
        => StageAndLaunchUpdateAsync(AgentUpdateStager.FromHeartbeat(response), requireElevation, ct);

    public async Task<bool> StageAndLaunchUpdateAsync(AgentUpdateSignal signal, bool requireElevation, CancellationToken ct)
    {
        // Server requests may stage and schedule policy; they are never local UI consent.
        return await AgentUpdateLocalService.CheckAndStageAsync(automatic: true, required: signal.Required, ct).ConfigureAwait(false) is not null;
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

}
