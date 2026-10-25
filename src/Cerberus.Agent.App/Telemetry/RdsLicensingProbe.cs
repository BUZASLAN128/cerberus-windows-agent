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
    // Runs inside the 5 s server section budget of the sessions section, next to the WTS enumeration.
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(2);

    public static async Task<RdsLicensingInfo> ReadAsync(CancellationToken ct)
    {
        try
        {
            return await Task.Run(() => Read(ReadLocalMachineValue), CancellationToken.None).WaitAsync(ReadTimeout, ct).ConfigureAwait(false);
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
    internal static RdsLicensingInfo Read(Func<string, string, object?> getValue)
    {
        if (getValue(TerminalServerKey, "TSAppCompat") is not 1)
            return RdsLicensingInfo.NotApplicable;

        var mode = MapLicensingMode(
            getValue(PolicyKey, "LicensingMode") as int?
            ?? getValue(LicensingCoreKey, "LicensingMode") as int?);
        // Grace days are only exposed through WMI, so they are not reported.
        return new RdsLicensingInfo("ok", true, mode, LicenseServerConfigured(getValue), null);
    }

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
}

internal sealed record RdsLicensingInfo(
    string Status,
    bool? RdshInstalled,
    string? LicensingMode,
    bool? LicenseServerConfigured,
    int? GraceDaysLeft)
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
    };
}
