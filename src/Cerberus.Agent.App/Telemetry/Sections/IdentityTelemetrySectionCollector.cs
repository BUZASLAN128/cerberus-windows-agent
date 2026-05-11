namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class IdentityTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "identity";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var metadata = context.Metadata;
        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            agent_version = metadata.AgentVersion,
            build_id = metadata.BuildId,
            build_channel = metadata.BuildChannel,
            boot_id = metadata.BootId,
            machine_name = Environment.MachineName,
            device_fingerprint = WindowsDeviceInfo.ComputeDeviceFingerprint(),
            user_interactive = Environment.UserInteractive,
        });
    }
}
