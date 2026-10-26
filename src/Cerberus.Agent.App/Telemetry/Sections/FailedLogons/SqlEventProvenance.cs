using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

/// <summary>
/// Application-log writes are open to any interactive user, so a provider name proves nothing; the event's ProcessId
/// is filled in by the Event Log service from the RPC caller and cannot be chosen by the writer. An 18456 is verified
/// only when that id is the current process of the service named like the provider and the event is not older than
/// that process. Anything unreadable (service missing or stopped, process gone, no ProcessId) is unverified.
/// </summary>
internal sealed class SqlEventProvenance
{
    private readonly Func<string, (int ProcessId, DateTimeOffset StartUtc)?> _lookup;
    private readonly Dictionary<string, (int ProcessId, DateTimeOffset StartUtc)?> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="lookup">Service name to its running process id and start time (null = unknown); defaults to the live lookup. Called once per service.</param>
    public SqlEventProvenance(Func<string, (int ProcessId, DateTimeOffset StartUtc)?>? lookup = null)
        => _lookup = lookup ?? LookupService;

    public bool IsVerified(string provider, int? eventProcessId, DateTimeOffset timeUtc)
    {
        if (eventProcessId is not { } pid || pid <= 0)
            return false;
        if (!_cache.TryGetValue(provider, out var service))
            _cache[provider] = service = _lookup(provider);
        return service is { } s && s.ProcessId == pid && timeUtc >= s.StartUtc;
    }

    /// <summary>The 18456 as a counted failure with its client address when verified; otherwise a bare unverified marker.</summary>
    public FailedLogonEvent Classify(string provider, int? eventProcessId, DateTimeOffset timeUtc, IReadOnlyList<string> fields)
        => IsVerified(provider, eventProcessId, timeUtc)
            ? new FailedLogonEvent(FailedLogonSource.Sql18456, timeUtc, FailedLogonClassifier.SqlClientIpFromFields(fields))
            : new FailedLogonEvent(FailedLogonSource.Sql18456Unverified, timeUtc, null);

    /// <summary>Running process of the named service through the service manager (not by image name).</summary>
    internal static (int ProcessId, DateTimeOffset StartUtc)? LookupService(string serviceName)
    {
        try
        {
            if (ServiceProcessId(serviceName) is not { } pid)
                return null;
            using var process = Process.GetProcessById(pid);
            return (pid, new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero));
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            return null;
        }
    }

    internal static int? ServiceProcessId(string serviceName)
    {
        const uint ScManagerConnect = 0x0001, ServiceQueryStatus = 0x0004, Running = 4;
        using var manager = OpenSCManagerW(null, null, ScManagerConnect);
        if (manager.IsInvalid)
            return null;
        using var service = OpenServiceW(manager, serviceName, ServiceQueryStatus);
        if (service.IsInvalid || !QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatusProcess>(), out _))
            return null;
        return status.CurrentState == Running && status.ProcessId is > 0 and <= int.MaxValue ? (int)status.ProcessId : null;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManagerW(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenServiceW(ServiceHandle manager, string service, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatusProcess status, int size, out int required);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode,
            CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }
}
