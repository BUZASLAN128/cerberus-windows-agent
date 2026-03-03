using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;
using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using System.Net.Http;
using System.IO;

namespace Cerberus.Agent.App;

internal static class ServiceMode
{
    public static async Task RunAsync(CancellationToken ct)
    {
        using var log = AgentFileLogger.CreateDefault(alsoConsole: true);
        log.Info("Service mode starting.");

        var secrets = new DpapiSecretStore(SecretStoreScope.Machine);
        var (_, _, privateKeyPem, storedBackendUrl, _, _) = await secrets.LoadAsync(ct);
        var backendUrl = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL") ?? storedBackendUrl;

        using var http = new HttpClient { BaseAddress = new Uri(backendUrl.TrimEnd('/')), Timeout = TimeSpan.FromSeconds(30) };

        var signer = new RequestSigner(privateKeyPem);
        var tokens = new AgentTokenManager(http, secrets);
        var api = new AgentApiClient(http, secrets, tokens, signer);

        var cachePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CerberusAgent",
            "idempotency.json");
        var idempotency = new IdempotencyCache(cachePath, maxEntries: 5000, ttl: TimeSpan.FromHours(24));

        var directoryProvider = new AdDirectoryProvider();

        var handlers = new List<ICommandHandler>
        {
            new HealthSnapshotHandler(),
            new TailscaleEnsureConnectedHandler(),
        };
        handlers.AddRange(AdUserCommandHandlers.CreateDefaultHandlers(directoryProvider));

        var dispatcher = new CommandDispatcher(handlers, idempotency);
        var statusProvider = new TailscaleStatusProvider();
        var loop = new HeartbeatLoop(
            api,
            dispatcher,
            minDelayOnError: TimeSpan.FromSeconds(10),
            statusProvider: statusProvider,
            adStatusProvider: _ => Task.FromResult<object?>(BuildAdStatus()),
            log: log);

        try
        {
            await loop.RunAsync(ct);
        }
        finally
        {
            log.Info("Service mode stopped.");
        }
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

    private sealed class TailscaleStatusProvider : IAgentStatusProvider
    {
        public async Task<object?> GetTailscaleAsync(CancellationToken ct)
        {
            var (installed, connected, snapshot, err) = await TailscaleStatusProbe.ProbeAsync(
                timeout: TimeSpan.FromSeconds(5),
                ct: ct);
            return new
            {
                installed,
                connected,
                error = err,
                status = snapshot,
            };
        }
    }

    private static object BuildAdStatus()
    {
        var (joined, domain, err) = AdStatusProbe.Probe();
        return new
        {
            domain_joined = joined,
            domain_name = domain,
            last_error = err,
        };
    }
}
