using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>TCP listeners and UDP endpoints with the owning image name. Addresses are reduced to a bind scope.</summary>
internal sealed class ListeningPortsTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    internal const int MaxPorts = 256;

    internal sealed record RawPort(string Protocol, string Family, int Port, string BindScope, string? ProcessName);

    public string SectionName => "listening_ports";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
        => ValueTask.FromResult(Build(PortsNative.Read(ct)));

    internal static object Build(IEnumerable<RawPort> raw)
    {
        var ports = raw
            .Select(p => new
            {
                protocol = p.Protocol,
                family = p.Family,
                port = p.Port,
                bind_scope = p.BindScope,
                process_name = ServerFactText.CleanOrNull(p.ProcessName, 64),
            })
            .Distinct()
            .OrderBy(p => p.protocol, StringComparer.Ordinal)
            .ThenBy(p => p.port)
            .ThenBy(p => p.family, StringComparer.Ordinal)
            .ThenBy(p => p.bind_scope, StringComparer.Ordinal)
            .ThenBy(p => p.process_name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new
        {
            status = "ok",
            port_count = ports.Length,
            truncated = ports.Length > MaxPorts,
            ports = ports.Take(MaxPorts).ToArray(),
        };
    }
}

internal static class PortsNative
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidListener = 3;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;

    private readonly record struct Layout(int RowSize, int AddressOffset, int AddressLength, int PortOffset, int PidOffset);

    private static readonly Layout Tcp4 = new(24, 4, 4, 8, 20);
    private static readonly Layout Tcp6 = new(56, 0, 16, 20, 52);
    private static readonly Layout Udp4 = new(12, 0, 4, 4, 8);
    private static readonly Layout Udp6 = new(28, 0, 16, 20, 24);

    public static IReadOnlyList<ListeningPortsTelemetrySectionCollector.RawPort> Read(CancellationToken ct)
    {
        var rows = new List<(string Protocol, string Family, int Port, string Scope, int Pid)>();
        ReadTable(true, AfInet, Tcp4, "tcp", "ipv4", ct, rows);
        ReadTable(true, AfInet6, Tcp6, "tcp", "ipv6", ct, rows);
        ReadTable(false, AfInet, Udp4, "udp", "ipv4", ct, rows);
        ReadTable(false, AfInet6, Udp6, "udp", "ipv6", ct, rows);

        var names = new Dictionary<int, string?>();
        return rows
            .Where(r => r.Port > 0)
            .Select(r =>
            {
                ct.ThrowIfCancellationRequested();
                if (!names.TryGetValue(r.Pid, out var name))
                    names[r.Pid] = name = ReadProcessName(r.Pid);
                return new ListeningPortsTelemetrySectionCollector.RawPort(r.Protocol, r.Family, r.Port, r.Scope, name);
            })
            .ToArray();
    }

    private static void ReadTable(
        bool tcp, int family, Layout layout, string protocol, string familyName,
        CancellationToken ct, List<(string Protocol, string Family, int Port, string Scope, int Pid)> rows)
    {
        var buffer = IntPtr.Zero;
        var size = 0;
        try
        {
            var loaded = false;
            for (var attempt = 0; attempt < 4 && !loaded; attempt++)
            {
                var status = tcp
                    ? GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidListener, 0)
                    : GetExtendedUdpTable(buffer, ref size, false, family, UdpTableOwnerPid, 0);
                if (status == 0)
                {
                    loaded = true;
                    break;
                }

                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
                if (status != ErrorInsufficientBuffer || size <= 0)
                    return;
                buffer = Marshal.AllocHGlobal(size);
            }

            if (!loaded)
                return;

            var count = Marshal.ReadInt32(buffer);
            for (var i = 0; i < count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var row = IntPtr.Add(buffer, 4 + i * layout.RowSize);
                var rawPort = Marshal.ReadInt32(row, layout.PortOffset);
                var port = ((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF);
                var address = new byte[layout.AddressLength];
                Marshal.Copy(IntPtr.Add(row, layout.AddressOffset), address, 0, layout.AddressLength);
                rows.Add((protocol, familyName, port, BindScope(address), Marshal.ReadInt32(row, layout.PidOffset)));
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }
    }

    internal static string BindScope(byte[] address)
    {
        if (address.All(b => b == 0))
            return "any";
        if (address.Length == 4)
            return address[0] == 127 ? "loopback" : "specific";
        return address.Take(15).All(b => b == 0) && address[15] == 1 ? "loopback" : "specific";
    }

    private static string? ReadProcessName(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.ProcessName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);
}
