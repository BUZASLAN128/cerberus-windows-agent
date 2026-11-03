using System.Collections;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>Read-only NLM category to adapter-ID mapping; categories do not describe open firewall ports.</summary>
internal static class FirewallAdapterProfiles
{
    internal const int MaxAdapters = 16; // Same active-adapter limit as the network section.
    private const int MaxConnections = 64;
    private static int _reading;
    internal sealed record Adapter(string Id, string Name);
    internal sealed record Connection(Guid AdapterId, int Category);

    internal static object[] Read(CancellationToken ct)
    {
        Adapter[] adapters;
        try
        {
            adapters = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Take(MaxAdapters).Select(n => new Adapter(n.Id, n.Name)).ToArray();
        }
        catch (NetworkInformationException)
        {
            return Array.Empty<object>();
        }
        if (Interlocked.CompareExchange(ref _reading, 1, 0) != 0)
            return Build(adapters, null);
        try
        {
            return Build(adapters, Probe(ct));
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or ArgumentException
            or InvalidOperationException or NotSupportedException or UnauthorizedAccessException
            or System.Security.SecurityException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            return Build(adapters, null);
        }
        finally
        {
            Volatile.Write(ref _reading, 0);
        }
    }

    internal static object[] Build(IEnumerable<Adapter> adapters, IEnumerable<Connection>? connections)
    {
        var byAdapter = (connections ?? Array.Empty<Connection>()).GroupBy(c => c.AdapterId)
            .ToDictionary(g => g.Key, g => g.Select(c => c.Category).Distinct().ToArray());
        return adapters.Take(MaxAdapters).Select(a =>
        {
            var category = Guid.TryParse(a.Id, out var id) && byAdapter.TryGetValue(id, out var categories)
                && categories.Length == 1 ? categories[0] : -1;
            var profile = category switch { 0 => "public", 1 => "private", 2 => "domain", _ => "unknown" };
            return (object)new
            {
                adapter_name = ServerFactText.Clean(a.Name, 128), profile,
                status = profile == "unknown" ? "unavailable" : "ok",
            };
        }).ToArray();
    }

    private static List<Connection>? Probe(CancellationToken ct)
    {
        object? manager = null, collection = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            var type = Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B"), throwOnError: true)!;
            manager = Activator.CreateInstance(type)!;
            collection = ((dynamic)manager).GetNetworkConnections();
            var result = new List<Connection>();
            var scanned = 0;
            foreach (var item in (IEnumerable)collection)
            {
                object? network = null;
                try
                {
                    ct.ThrowIfCancellationRequested();
                    // An incomplete scan cannot rule out conflicting categories for the same adapter.
                    if (++scanned > MaxConnections)
                        return null;
                    var connection = (INetworkConnection)item;
                    if (!connection.IsConnected)
                        continue;
                    network = connection.GetNetwork();
                    result.Add(new Connection(connection.GetAdapterId(), (int)((dynamic)network).GetCategory()));
                }
                finally
                {
                    Release(network);
                    Release(item);
                }
            }
            return result;
        }
        finally
        {
            Release(collection);
            Release(manager);
        }
    }

    private static void Release(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
            Marshal.ReleaseComObject(value);
    }

    // Vtable order from Windows SDK netlistmgr.h. Typed interop avoids Automation GUID-return conversion.
    [ComImport, Guid("DCB00005-570F-4A9B-8D69-199FDBA5723B"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
    private interface INetworkConnection
    {
        [return: MarshalAs(UnmanagedType.Interface)] object GetNetwork();
        bool IsConnectedToInternet { [return: MarshalAs(UnmanagedType.VariantBool)] get; }
        bool IsConnected { [return: MarshalAs(UnmanagedType.VariantBool)] get; }
        int GetConnectivity();
        Guid GetConnectionId();
        Guid GetAdapterId();
    }
}
