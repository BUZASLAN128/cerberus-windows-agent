using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class CapabilitiesTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    private readonly LocalUserCommandPolicy _localUserPolicy;

    public CapabilitiesTelemetrySectionCollector()
        : this(LocalUserCommandPolicy.FromEnvironmentAndRegistry())
    {
    }

    internal CapabilitiesTelemetrySectionCollector(LocalUserCommandPolicy localUserPolicy)
    {
        _localUserPolicy = localUserPolicy;
    }

    public string SectionName => "capabilities";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var mutation = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["windows.local_user.disable"] = "managed_local_user",
            ["windows.local_user.delete"] = "managed_local_user",
            ["local_users"] = "managed_cerberus_users",
            ["local_groups"] = "remote_desktop_users_managed",
            ["windows_services"] = "governed_boundary_disabled",
            ["firewall"] = "governed_boundary_disabled",
            ["rdp"] = "managed_local_user_credential_ready",
            ["ad"] = "planned_governed_module",
        };
        if (_localUserPolicy.CreateEnabled)
        {
            mutation["windows.local_user.create"] = "managed_local_user";
        }

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
            mutation,
            arbitrary_command_execution = "unsupported",
        });
    }
}
