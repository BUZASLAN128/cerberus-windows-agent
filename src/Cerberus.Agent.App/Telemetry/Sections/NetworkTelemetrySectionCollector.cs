using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;

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
                    .Select(a => RedactAddress(a.Address))
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

    internal static object RedactAddress(IPAddress address)
    {
        var family = address.AddressFamily == AddressFamily.InterNetwork ? "ipv4" : "ipv6";
        var scope = IsPrivateOrLocal(address) ? "private" : "public";

        return new
        {
            family,
            scope,
            value = $"{scope}-{family}",
        };
    }

    private static bool IsPrivateOrLocal(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return true;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 10 ||
                   bytes[0] == 127 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 169 && bytes[1] == 254);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal ||
                   address.IsIPv6SiteLocal ||
                   address.IsIPv6Teredo ||
                   address.Equals(IPAddress.IPv6Loopback) ||
                   IsUniqueLocalIpv6(address);
        }

        return true;
    }

    private static bool IsUniqueLocalIpv6(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return (bytes[0] & 0xfe) == 0xfc;
    }
}
