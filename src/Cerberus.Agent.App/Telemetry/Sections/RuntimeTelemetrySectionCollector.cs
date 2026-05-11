using System.Diagnostics;
using System.IO;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class RuntimeTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "runtime";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        using var process = Process.GetCurrentProcess();
        var service = AgentStatus.GetService();
        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            runtime_mode = Environment.UserInteractive ? "interactive" : "service",
            process_id = Environment.ProcessId,
            process_started_at_utc = process.StartTime.ToUniversalTime().ToString("O"),
            uptime_seconds = Environment.TickCount64 / 1000,
            working_set_mb = TelemetryValue.ToMb(process.WorkingSet64),
            service = new
            {
                name = ServiceInstaller.ServiceName,
                installed = service.Installed,
                state = service.Text,
            },
            registration = new
            {
                user_scope_present = File.Exists(DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.User)),
                machine_scope_present = File.Exists(DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.Machine)),
            },
            self_throttling = new
            {
                active = false,
                reason = (string?)null,
            },
        });
    }
}
