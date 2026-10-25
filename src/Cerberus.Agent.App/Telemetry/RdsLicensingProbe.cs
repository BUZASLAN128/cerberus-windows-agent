using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry;

/// <summary>
/// Reads Remote Desktop Session Host licensing facts from the registry (no WMI, which endpoint
/// protection products block). License server names are never returned, only whether one is configured.
/// </summary>
internal static class RdsLicensingProbe
{
    private const string TerminalServerKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string LicensingCoreKey = TerminalServerKey + @"\RCM\Licensing Core";
    private const string PolicyKey = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    private const string TermServiceParametersKey = @"SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers";
    private const string GracePeriodKey = TerminalServerKey + @"\RCM\GracePeriod";
    private const string RdshComponentKey = @"SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\RDS-RD-Server";
    private const int GracePeriodDays = 120;
    // Runs inside the 5 s server section budget of the sessions section, next to the WTS enumeration.
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(2);

    public static async Task<RdsLicensingInfo> ReadAsync(CancellationToken ct)
    {
        try
        {
            return await Task.Run(() => Read(ReadLocalMachineValue, ReadGracePeriodLastWriteUtc, TimeProvider.System), CancellationToken.None).WaitAsync(ReadTimeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return RdsLicensingInfo.Unavailable;
        }
    }

    // getValue(subKey, valueName) reads HKLM (64-bit view) and returns null when the key or value is missing.
    // readGraceLastWriteUtc returns the last-write time of the GracePeriod key, or null when it is missing, unreadable or empty.
    internal static RdsLicensingInfo Read(
        Func<string, string, object?> getValue,
        Func<DateTime?>? readGraceLastWriteUtc = null,
        TimeProvider? time = null)
    {
        if (!IsRdshInstalled(getValue(RdshComponentKey, "InstallState"), getValue(TerminalServerKey, "TSAppCompat")))
            return RdsLicensingInfo.NotApplicable;

        var mode = MapLicensingMode(
            getValue(PolicyKey, "LicensingMode") as int?
            ?? getValue(LicensingCoreKey, "LicensingMode") as int?);
        // The remaining grace days are only exposed through WMI (grace_days_left stays null); the estimate comes
        // from the key's creation-time write, because the value itself is encrypted and is never parsed.
        var graceStart = readGraceLastWriteUtc?.Invoke();
        var graceStartUtc = graceStart is { } t ? DateTime.SpecifyKind(t, DateTimeKind.Utc) : (DateTime?)null;
        var now = (time ?? TimeProvider.System).GetUtcNow().UtcDateTime;
        return new RdsLicensingInfo("ok", true, mode, LicenseServerConfigured(getValue), null,
            graceStartUtc?.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture),
            graceStartUtc is { } start ? EstimateGraceDaysLeft(start, now) : null);
    }

    // The RDSH role is installed when Server Manager's component cache says so (InstallState 1); TSAppCompat is the
    // application compatibility mode and stays as a fallback only.
    internal static bool IsRdshInstalled(object? installState, object? tsAppCompat) => installState is 1 || tsAppCompat is 1;

    // WMI counts a started day as used: 120 - ceil(elapsed days), clamped to [0, 120].
    internal static int EstimateGraceDaysLeft(DateTime startUtc, DateTime nowUtc)
        => (int)Math.Clamp(GracePeriodDays - Math.Ceiling((nowUtc - startUtc).TotalDays), 0, GracePeriodDays);

    // LicensingMode: 2 = per device, 4 = per user, 5 = not configured.
    internal static string MapLicensingMode(int? licensingType) => licensingType switch
    {
        2 => "per_device",
        4 => "per_user",
        null or 0 or 5 => "not_configured",
        _ => "unknown",
    };

    private static bool LicenseServerConfigured(Func<string, string, object?> getValue)
    {
        if (getValue(PolicyKey, "LicenseServers") is string policyServers && !string.IsNullOrWhiteSpace(policyServers))
            return true;
        return getValue(TermServiceParametersKey, "SpecifiedLicenseServers") is string[] list
            && list.Any(s => !string.IsNullOrWhiteSpace(s));
    }

    private static object? ReadLocalMachineValue(string subKey, string name)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.OpenSubKey(subKey, writable: false);
        return key?.GetValue(name);
    }

    private static DateTime? ReadGracePeriodLastWriteUtc()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(GracePeriodKey, writable: false);
            if (key is null)
                return null;
            var handle = key.Handle.DangerousGetHandle();
            var rc = RegQueryInfoKey(handle, null, IntPtr.Zero, IntPtr.Zero, out _, out _, out _, out var valueCount,
                out _, out _, IntPtr.Zero, out var lastWrite);
            if (rc != 0 || valueCount == 0 || lastWrite == 0)
                return null;
            return DateTime.FromFileTimeUtc(lastWrite);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            // The GracePeriod key is ACL-restricted; only the grace fields go missing, not the whole section.
            return null;
        }
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryInfoKeyW")]
    private static extern int RegQueryInfoKey(
        IntPtr hKey, char[]? lpClass, IntPtr lpcchClass, IntPtr lpReserved,
        out uint lpcSubKeys, out uint lpcbMaxSubKeyLen, out uint lpcbMaxClassLen, out uint lpcValues,
        out uint lpcbMaxValueNameLen, out uint lpcbMaxValueLen, IntPtr lpSecurityDescriptor, out long lpftLastWriteTime);
}

internal sealed record RdsLicensingInfo(
    string Status,
    bool? RdshInstalled,
    string? LicensingMode,
    bool? LicenseServerConfigured,
    int? GraceDaysLeft,
    string? GraceStartedUtc = null,
    int? GraceDaysLeftEstimate = null)
{
    internal static readonly RdsLicensingInfo NotApplicable = new("not_applicable", false, null, null, null);
    internal static readonly RdsLicensingInfo Unavailable = new("unavailable", null, null, null, null);

    internal object ToPayload() => new
    {
        status = Status,
        rdsh_installed = RdshInstalled,
        licensing_mode = LicensingMode,
        license_server_configured = LicenseServerConfigured,
        grace_days_left = GraceDaysLeft,
        grace_started_utc = GraceStartedUtc,
        grace_days_left_estimate = GraceDaysLeftEstimate,
    };
}
