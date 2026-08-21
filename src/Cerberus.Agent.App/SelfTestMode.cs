using Cerberus.Agent.Core;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.Integrations.Ad;
using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using System.IO;
using System.Net.Http;
using System.Text.Json;

namespace Cerberus.Agent.App;

internal static class SelfTestMode
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(bool json, string? outFile, CancellationToken ct)
    {
        using var log = AgentFileLogger.CreateUser(alsoConsole: !json);

        var started = DateTimeOffset.UtcNow;
        var report = new SelfTestReport
        {
            StartedAtUtc = started,
            AgentVersion = WindowsDeviceInfo.GetAgentVersion(),
            MachineName = Environment.MachineName,
            UserInteractive = Environment.UserInteractive,
        };

        // Offline probes always run.
        report.Steps.Add(SelfTestStep.Ok("offline.device", "Device info ok"));

        var (tailscaleInstalled, tailscaleConnected, _, tailscaleErr) = await TailscaleStatusProbe.ProbeAsync(
            timeout: TimeSpan.FromSeconds(5),
            ct: ct);
        report.Steps.Add(SelfTestStep.Ok(
            "offline.tailscale.probe",
            $"Tailscale probed (installed={tailscaleInstalled}, connected={tailscaleConnected})",
            data: new { installed = tailscaleInstalled, connected = tailscaleConnected, error = tailscaleErr }));

        var (adJoined, adDomain, adErr) = AdStatusProbe.Probe();
        report.Steps.Add(SelfTestStep.Ok(
            "offline.ad.probe",
            $"AD probed (joined={adJoined})",
            data: new { joined = adJoined, domain = adDomain, error = adErr }));

        try
        {
            var collector = new WindowsTelemetryCollector();
            var snapshot = await collector.BuildSnapshotAsync(
                BuildMetadata(),
                lastHeartbeat: null,
                ct: ct).ConfigureAwait(false);
            report.Steps.Add(SelfTestStep.Ok(
                "offline.telemetry.snapshot",
                "Telemetry snapshot built locally without submitting.",
                data: new
                {
                    sections = snapshot.Sections.Keys.OrderBy(k => k).ToArray(),
                    payload_bytes = AgentTelemetryLimits.EstimateJsonBytes(snapshot),
                }));
        }
        catch (Exception ex)
        {
            report.Steps.Add(SelfTestStep.Fail("offline.telemetry.snapshot", "Telemetry snapshot build failed", ex));
        }

        // Online probes require stored agent secrets (at least refresh token + signing key).
        var userSecrets = await TryLoadSecretsAsync(scope: SecretStoreScope.User, ct: ct);
        var machineSecrets = userSecrets is null
            ? await TryLoadSecretsAsync(scope: SecretStoreScope.Machine, ct: ct)
            : null;

        var secrets = userSecrets?.Store ?? machineSecrets?.Store;
        var scopeUsed = userSecrets?.Scope ?? machineSecrets?.Scope;
        var backendUrl = (Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL")
                          ?? userSecrets?.BackendUrl
                          ?? machineSecrets?.BackendUrl
                          ?? "")
            .Trim()
            .TrimEnd('/');

        if (secrets is null || string.IsNullOrWhiteSpace(backendUrl))
        {
            report.Steps.Add(SelfTestStep.Skip(
                "online.prereq",
                "Online checks skipped (agent not registered yet). Run tray onboarding first."));
            Finalize(report, started);
            return await EmitAsync(report, json: json, outFile: outFile, log: log, ct: ct);
        }

        report.Steps.Add(SelfTestStep.Ok(
            "online.prereq",
            $"Using stored secrets (scope={scopeUsed}) and configured backend."));

        using var http = new HttpClient
        {
            BaseAddress = new Uri(backendUrl),
            Timeout = TimeSpan.FromSeconds(30),
        };

        // Minimal health check.
        try
        {
            using var resp = await http.GetAsync("/health", ct);
            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"Health check failed: {(int)resp.StatusCode} {resp.ReasonPhrase}");
            report.Steps.Add(SelfTestStep.Ok("online.backend.health", "Backend /health ok"));
        }
        catch (Exception ex)
        {
            report.Steps.Add(SelfTestStep.Fail("online.backend.health", "Backend /health failed", ex));
            Finalize(report, started);
            return await EmitAsync(report, json: json, outFile: outFile, log: log, ct: ct);
        }

        report.Steps.Add(SelfTestStep.Skip(
            "online.agent.telemetry_submit",
            "Self-test is read-only in 7FC; heartbeat, snapshot, preauth, and tailscale export are not submitted."));

        Finalize(report, started);
        return await EmitAsync(report, json: json, outFile: outFile, log: log, ct: ct);
    }

    private static void Finalize(SelfTestReport report, DateTimeOffset started)
    {
        report.FinishedAtUtc = DateTimeOffset.UtcNow;
        report.DurationSeconds = (int)Math.Max(0, (report.FinishedAtUtc.Value - started).TotalSeconds);
    }

    private static AgentBuildMetadata BuildMetadata() => new(
        AgentVersion: WindowsDeviceInfo.GetAgentVersion(),
        BuildId: WindowsDeviceInfo.GetBuildId(),
        BuildChannel: WindowsDeviceInfo.GetBuildChannel(),
        BootId: Guid.NewGuid().ToString("N"),
        SupportedSchemaVersions: AgentSchemaVersions.All);

    private sealed class LoadedSecrets
    {
        public required ISecretStore Store { get; init; }
        public required SecretStoreScope Scope { get; init; }
        public required string BackendUrl { get; init; }
    }

    private static async Task<LoadedSecrets?> TryLoadSecretsAsync(SecretStoreScope scope, CancellationToken ct)
    {
        try
        {
            var store = new DpapiSecretStore(scope);
            var (_, _, _, backendUrl, _, _) = await store.LoadAsync(ct);
            return new LoadedSecrets { Store = store, Scope = scope, BackendUrl = backendUrl ?? "" };
        }
        catch
        {
            return null;
        }
    }

    private static async Task<int> EmitAsync(SelfTestReport report, bool json, string? outFile, AgentFileLogger log, CancellationToken ct)
    {
        // Derive overall status.
        report.Overall = report.Steps.Any(s => s.Status == "fail")
            ? "fail"
            : report.Steps.All(s => s.Status == "skip")
                ? "skip"
                : "ok";

        var payload = JsonSerializer.Serialize(report, JsonOpts);
        payload = Sanitizer.Redact(payload);

        if (!string.IsNullOrWhiteSpace(outFile))
        {
            var p = outFile.Trim();
            Directory.CreateDirectory(Path.GetDirectoryName(p)!);
            await File.WriteAllTextAsync(p, payload, ct);
        }

        if (json)
        {
            Console.WriteLine(payload);
        }
        else
        {
            log.Info($"Self-test overall: {report.Overall}");
            foreach (var s in report.Steps)
                log.Info($"[{s.Status}] {s.Id}: {s.Message}");
        }

        return report.Overall == "ok" ? 0 : 2;
    }
}

internal sealed class SelfTestReport
{
    public string Schema { get; set; } = "cerberus-agent-selftest.v1";
    public string? Overall { get; set; }
    public DateTimeOffset StartedAtUtc { get; set; }
    public DateTimeOffset? FinishedAtUtc { get; set; }
    public int DurationSeconds { get; set; }
    public string? AgentVersion { get; set; }
    public string? MachineName { get; set; }
    public bool UserInteractive { get; set; }
    public List<SelfTestStep> Steps { get; } = new();
}

internal sealed class SelfTestStep
{
    public required string Id { get; init; }
    public required string Status { get; init; } // ok|fail|skip
    public required string Message { get; init; }
    public object? Data { get; init; }
    public string? Error { get; init; }

    public static SelfTestStep Ok(string id, string message, object? data = null) =>
        new() { Id = id, Status = "ok", Message = message, Data = data };

    public static SelfTestStep Skip(string id, string message) =>
        new() { Id = id, Status = "skip", Message = message };

    public static SelfTestStep Fail(string id, string message, Exception ex) =>
        new()
        {
            Id = id,
            Status = "fail",
            Message = message,
            Error = Sanitizer.Redact($"{ex.GetType().Name}: {ex.Message}"),
        };
}
