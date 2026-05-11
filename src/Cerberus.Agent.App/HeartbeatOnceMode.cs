using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using System.Net.Http;

namespace Cerberus.Agent.App;

internal static class HeartbeatOnceMode
{
    public static async Task<int> RunAsync(CancellationToken ct)
    {
        using var log = AgentFileLogger.CreateDefault(alsoConsole: true);
        try
        {
            var secrets = new DpapiSecretStore(SecretStoreScope.User);
            var (_, _, privateKeyPem, storedBackendUrl, _, _) = await secrets.LoadAsync(ct);
            var backendUrl = (Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL") ?? storedBackendUrl).Trim().TrimEnd('/');
            if (!Uri.TryCreate(backendUrl, UriKind.Absolute, out var backend))
                throw new InvalidOperationException("Stored backend URL is invalid.");

            using var http = new HttpClient { BaseAddress = backend, Timeout = TimeSpan.FromSeconds(30) };
            var api = new AgentApiClient(
                http,
                secrets,
                new AgentTokenManager(http, secrets),
                new RequestSigner(privateKeyPem));

            var metadata = new AgentBuildMetadata(
                AgentVersion: WindowsDeviceInfo.GetAgentVersion(),
                BuildId: WindowsDeviceInfo.GetBuildId(),
                BuildChannel: WindowsDeviceInfo.GetBuildChannel(),
                BootId: Guid.NewGuid().ToString("N"),
                SupportedSchemaVersions: AgentSchemaVersions.All);

            var heartbeat = await api.HeartbeatAsync(new
            {
                status = "connected",
                agent_version = metadata.AgentVersion,
                build_id = metadata.BuildId,
                build_channel = metadata.BuildChannel,
                runtime_mode = "heartbeat_once",
                supported_schema_versions = metadata.SupportedSchemaVersions,
                tailscale = await new TailscaleStatusProvider().GetTailscaleAsync(ct),
                ad = BuildAdStatus(),
                capabilities = Array.Empty<string>(),
            }, ct);

            var control = await new HeartbeatResponseHandler(secrets, log).HandleAsync(heartbeat, ct);
            if (control == HeartbeatControlAction.Stop)
                return 0;

            await api.SubmitEventsAsync(AgentTelemetryFactory.CreateEvents(
                metadata,
                new[]
                {
                    new AgentEventItem(
                        EventId: $"agent.started:{metadata.BootId}",
                        Type: "agent.started",
                        OccurredAt: DateTimeOffset.UtcNow.ToString("O"),
                        Severity: "info",
                        Payload: new Dictionary<string, object?>
                        {
                            ["boot_id"] = metadata.BootId,
                            ["agent_version"] = metadata.AgentVersion,
                        }),
                }), ct);

            var snapshot = await new WindowsTelemetryCollector().BuildSnapshotAsync(metadata, heartbeat, ct);
            await api.SubmitSnapshotAsync(snapshot, ct);
            log.Info("Heartbeat-once completed: heartbeat, started event, and snapshot submitted.");
            return 0;
        }
        catch (Exception ex)
        {
            log.Error("Heartbeat-once failed.", ex);
            return 2;
        }
    }

    private static object BuildAdStatus()
    {
        var (joined, domain, err) = Cerberus.Agent.Integrations.Ad.AdStatusProbe.Probe();
        return new
        {
            domain_joined = joined,
            domain_name = domain,
            last_error = err,
        };
    }

    private sealed class TailscaleStatusProvider : IAgentStatusProvider
    {
        public async Task<object?> GetTailscaleAsync(CancellationToken ct)
        {
            var (installed, connected, snapshot, error) = await Cerberus.Agent.Integrations.Tailscale.TailscaleStatusProbe.ProbeAsync(
                timeout: TimeSpan.FromSeconds(5),
                ct: ct);
            return new
            {
                installed,
                connected,
                error = Sanitizer.Redact(error),
                state = ExtractSnapshotValue(snapshot, "state"),
                ips = ExtractSnapshotValue(snapshot, "ips") ?? Array.Empty<string>(),
                status = snapshot,
            };
        }
    }

    private static object? ExtractSnapshotValue(object? snapshot, string key)
    {
        return snapshot is IReadOnlyDictionary<string, object?> map && map.TryGetValue(key, out var value)
            ? value
            : null;
    }
}
