using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class NetworkTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "network";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var adapters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .Take(16)
            .Select(n =>
            {
                var props = n.GetIPProperties();
                var ips = props.UnicastAddresses
                    .Where(a => a.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                    .Select(a => a.Address.ToString())
                    .Take(8)
                    .ToArray();

                return new
                {
                    name = n.Name,
                    type = n.NetworkInterfaceType.ToString(),
                    status = n.OperationalStatus.ToString(),
                    ip_addresses = ips,
                    has_gateway = props.GatewayAddresses.Count > 0,
                    dns_suffix_present = !string.IsNullOrWhiteSpace(props.DnsSuffix),
                };
            })
            .ToArray();

        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            adapter_count = adapters.Length,
            adapters,
        });
    }
}
