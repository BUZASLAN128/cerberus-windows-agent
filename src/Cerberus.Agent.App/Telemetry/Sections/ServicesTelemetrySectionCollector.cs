using System.ServiceProcess;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>Installed Windows services with state and start type. Binary paths are never read.</summary>
internal sealed class ServicesTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    internal const int MaxServices = 400;

    internal sealed record RawService(string? Name, string? DisplayName, string State, string StartType);

    public string SectionName => "services";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
        => ValueTask.FromResult(Build(Read(ct)));

    internal static object Build(IEnumerable<RawService> raw)
    {
        var services = raw
            .Select(s => new
            {
                name = ServerFactText.Clean(s.Name, 64),
                display_name = ServerFactText.Clean(s.DisplayName, 128),
                state = s.State,
                start_type = s.StartType,
            })
            .Where(s => s.name.Length > 0)
            .OrderBy(s => s.name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(s => s.name, StringComparer.Ordinal)
            .ToArray();

        return new
        {
            status = "ok",
            service_count = services.Length,
            truncated = services.Length > MaxServices,
            services = services.Take(MaxServices).ToArray(),
        };
    }

    private static List<RawService> Read(CancellationToken ct)
    {
        var result = new List<RawService>();
        foreach (var service in ServiceController.GetServices())
        {
            using (service)
            {
                ct.ThrowIfCancellationRequested();
                result.Add(new RawService(
                    service.ServiceName,
                    service.DisplayName,
                    MapState(service.Status),
                    ReadStartType(service)));
            }
        }

        return result;
    }

    internal static string MapState(ServiceControllerStatus status) => status switch
    {
        ServiceControllerStatus.Running => "running",
        ServiceControllerStatus.Stopped => "stopped",
        ServiceControllerStatus.StartPending => "start_pending",
        ServiceControllerStatus.StopPending => "stop_pending",
        ServiceControllerStatus.Paused => "paused",
        _ => "other",
    };

    private static string ReadStartType(ServiceController service)
    {
        try
        {
            return service.StartType switch
            {
                ServiceStartMode.Boot => "boot",
                ServiceStartMode.System => "system",
                ServiceStartMode.Automatic => IsDelayedAutoStart(service.ServiceName) ? "auto_delayed" : "auto",
                ServiceStartMode.Manual => "manual",
                ServiceStartMode.Disabled => "disabled",
                _ => "other",
            };
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return "other";
        }
    }

    private static bool IsDelayedAutoStart(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName);
            return key?.GetValue("DelayedAutostart") is int value && value != 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }
}
