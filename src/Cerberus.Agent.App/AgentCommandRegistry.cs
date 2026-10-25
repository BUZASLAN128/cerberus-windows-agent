using Cerberus.Agent.Core;
#if CERBERUS_SERVER_PROFILE
using Cerberus.Agent.App.Commands;
#else
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Integrations.Ad;
using Cerberus.Agent.Integrations.Tailscale;
#endif

namespace Cerberus.Agent.App;

/// <summary>
/// Command handlers registered by the service, per build profile. The server build registers exactly
/// <c>ping</c>, <c>collect_facts</c> and <c>agent_state</c>; the desktop list is the one the service always used.
/// </summary>
internal static class AgentCommandRegistry
{
#if CERBERUS_SERVER_PROFILE
    public static IReadOnlyList<ICommandHandler> CreateServer(AgentBuildMetadata metadata, AgentStateCommandHandler agentState)
        => new ICommandHandler[]
        {
            new PingCommandHandler(metadata),
            new CollectFactsCommandHandler(metadata),
            agentState ?? throw new ArgumentNullException(nameof(agentState)),
        };
#else
    public static IReadOnlyList<ICommandHandler> CreateDesktop(
        AgentApiClient api,
        AgentIdentity identity,
        IAgentLifecycleStateStore lifecycleState,
        ManagedAccountManifestPolicy managedAccounts,
        AgentDiagnosticBundleUploader diagnosticUploader,
        Func<AgentUpdateCoordinator?> updateCoordinator,
        AgentUpdateStateStore updateStateStore,
        IAgentLogger log,
        string agentVersion)
    {
        var handlers = new List<ICommandHandler>
        {
            new HealthSnapshotHandler(),
            new RdpQuickTestHandler(),
            new TailscaleEnsureConnectedHandler(),
        };
        handlers.Add(new DiagnosticBundleCollectCommandHandler(diagnosticUploader));
        handlers.AddRange(LocalUserCommandHandlers.CreateDefaultHandlers(manifest: managedAccounts));
        var adUsers = new ScopedAdUserProvider(identity, new ProtectedAdScopePolicy(),
            new WindowsAdDirectoryBoundary(), new ProtectedAdOwnershipStore());
        handlers.AddRange(ScopedAdCommandHandlers.CreateDefaultHandlers(identity, lifecycleState,
            api.GetAdCommandAuthorityAsync, adUsers));
        handlers.Add(new AgentUpdateRequestCommandHandler(
            updateCoordinator,
            updateStateStore,
            log,
            agentVersion));
        return handlers;
    }

    private sealed class HealthSnapshotHandler : ICommandHandler
    {
        public string Type => "agent.health.snapshot";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            var post = new
            {
                version = "v1",
                uptime_seconds = (long)Environment.TickCount64 / 1000,
                machine_name = Environment.MachineName,
                os_version = Environment.OSVersion.VersionString,
            };
            return Task.FromResult(new CommandResult("DONE", 0, null, null, post));
        }
    }

    private sealed class RdpQuickTestHandler : ICommandHandler
    {
        public string Type => "agent.rdp.quick_test";

        public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            var collector = new Telemetry.Sections.RdpTelemetrySectionCollector();
            var rdp = await collector.CollectAsync(
                new WindowsTelemetryContext(
                    new AgentBuildMetadata(
                        AgentVersion: WindowsDeviceInfo.GetAgentVersion(),
                        BuildId: WindowsDeviceInfo.GetBuildId(),
                        BuildChannel: WindowsDeviceInfo.GetBuildChannel(),
                        BootId: Guid.NewGuid().ToString("N"),
                        SupportedSchemaVersions: AgentSchemaVersions.All),
                    LastHeartbeat: null),
                ct).ConfigureAwait(false);

            return new CommandResult(
                "DONE",
                0,
                null,
                null,
                new
                {
                    source = "agent.rdp.quick_test",
                    rdp,
                });
        }
    }
#endif
}
