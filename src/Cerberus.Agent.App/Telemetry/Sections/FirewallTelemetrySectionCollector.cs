using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class FirewallTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "firewall";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            profiles = new[]
            {
                ReadProfile("DomainProfile", "domain"),
                ReadProfile("PublicProfile", "public"),
                ReadProfile("StandardProfile", "private"),
            },
        });
    }

    private static object ReadProfile(string profileKey, string name)
    {
        var enabled = TelemetryValue.ReadDword(
            Registry.LocalMachine,
            @$"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profileKey}",
            "EnableFirewall");

        return new
        {
            name,
            enabled = enabled.HasValue ? (bool?)(enabled.Value == 1) : null,
            status = enabled.HasValue ? "ok" : "unavailable",
        };
    }
}
