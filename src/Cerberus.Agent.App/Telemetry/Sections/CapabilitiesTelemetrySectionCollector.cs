namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class CapabilitiesTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "capabilities";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            read = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["identity"] = "supported",
                ["os"] = "supported",
                ["resources"] = "supported",
                ["network"] = "supported",
                ["tailscale"] = "supported_when_installed",
                ["rdp"] = "supported",
                ["firewall"] = "supported",
                ["security"] = "best_effort",
                ["clock"] = "supported",
                ["runtime"] = "supported",
            },
            mutation = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["windows.local_user.create_test"] = "lab_only",
                ["windows.local_user.disable_test"] = "lab_only",
                ["windows.local_user.delete_test"] = "lab_only",
                ["local_users"] = "lab_only_for_cerbtest_prefix",
                ["local_groups"] = "governed_boundary_disabled",
                ["windows_services"] = "governed_boundary_disabled",
                ["firewall"] = "governed_boundary_disabled",
                ["rdp"] = "governed_boundary_disabled",
                ["ad"] = "planned_governed_module",
            },
            arbitrary_command_execution = "unsupported",
        });
    }
}
