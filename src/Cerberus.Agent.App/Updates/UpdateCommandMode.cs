using System.Net.Http;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static class UpdateCommandMode
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(bool apply, CancellationToken ct)
    {
        var stateStore = AgentUpdateStateStore.CreateDefault();
        var currentVersion = WindowsDeviceInfo.GetAgentVersion();
        var signal = AgentUpdateTrustFactory.BuildConfiguredManualSignal();
        if (signal is null)
        {
            await stateStore.WriteTransitionAsync(
                AgentUpdateStates.Failed,
                currentVersion,
                ct,
                errorCode: AgentUpdateErrorCodes.NotConfigured,
                errorMessage: "Update trust is not configured.",
                markChecked: true).ConfigureAwait(false);
            WriteResult(new { available = false, state = AgentUpdateStates.Failed, error_code = AgentUpdateErrorCodes.NotConfigured });
            return 2;
        }

        await stateStore.WriteTransitionAsync(
            AgentUpdateStates.Checking,
            currentVersion,
            ct,
            manifestUrl: signal.ManifestUrl,
            markChecked: false).ConfigureAwait(false);

        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
            var coordinator = AgentUpdateTrustFactory.BuildCoordinator(http, NullAgentLogger.Instance, stateStore)
                ?? throw new InvalidOperationException("Update trust is not configured.");
            var check = await coordinator.CheckUpdateAsync(signal, ct).ConfigureAwait(false);
            if (!check.Available)
            {
                await stateStore.WriteTransitionAsync(
                    AgentUpdateStates.Current,
                    currentVersion,
                    ct,
                    targetVersion: check.Version,
                    channel: check.Channel ?? signal.Channel,
                    manifestUrl: check.ManifestUrl ?? signal.ManifestUrl,
                    markChecked: true).ConfigureAwait(false);
                WriteResult(new
                {
                    available = false,
                    state = AgentUpdateStates.Current,
                    current_version = currentVersion,
                    latest_version = check.Version,
                    manifest_url = signal.ManifestUrl,
                });
                return apply ? 3 : 0;
            }

            if (!apply)
            {
                await stateStore.WriteTransitionAsync(
                    AgentUpdateStates.Available,
                    currentVersion,
                    ct,
                    targetVersion: check.Version,
                    channel: check.Channel ?? signal.Channel,
                    manifestUrl: check.ManifestUrl ?? signal.ManifestUrl,
                    markChecked: true).ConfigureAwait(false);
                WriteResult(new
                {
                    available = true,
                    state = AgentUpdateStates.Available,
                    current_version = currentVersion,
                    target_version = check.Version,
                    channel = check.Channel,
                    manifest_url = check.ManifestUrl ?? signal.ManifestUrl,
                });
                return 0;
            }

            if (!Elevation.IsAdministrator())
                throw new InvalidOperationException("Administrator privileges are required to run a silent agent update.");

            var launched = await coordinator
                .StageAndLaunchUpdateAsync(signal, requireElevation: false, ct)
                .ConfigureAwait(false);
            WriteResult(new
            {
                available = true,
                state = launched ? AgentUpdateStates.InstallerStarted : AgentUpdateStates.Current,
                current_version = currentVersion,
                target_version = check.Version,
                channel = check.Channel,
                manifest_url = check.ManifestUrl ?? signal.ManifestUrl,
                updater_launched = launched,
            });
            return launched ? 0 : 3;
        }
        catch (Exception ex)
        {
            var errorCode = AgentUpdateErrorCodes.Classify(ex);
            await stateStore.WriteTransitionAsync(
                AgentUpdateStates.Failed,
                currentVersion,
                CancellationToken.None,
                channel: signal.Channel,
                manifestUrl: signal.ManifestUrl,
                errorCode: errorCode,
                errorMessage: ex.Message,
                markChecked: true).ConfigureAwait(false);
            WriteResult(new
            {
                available = false,
                state = AgentUpdateStates.Failed,
                error_code = errorCode,
                error_message = ex.Message,
                manifest_url = signal.ManifestUrl,
            }, error: true);
            return 2;
        }
    }

    private static void WriteResult(object result, bool error = false)
    {
        var json = JsonSerializer.Serialize(result, JsonOptions);
        if (error)
            Console.Error.WriteLine(json);
        else
            Console.WriteLine(json);
    }
}
