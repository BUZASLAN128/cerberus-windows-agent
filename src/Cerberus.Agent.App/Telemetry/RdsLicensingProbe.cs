using System.Management;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry;

/// <summary>
/// Reads Remote Desktop Session Host licensing facts from the TerminalServices WMI namespace.
/// License server names are never returned, only whether one is configured.
/// </summary>
internal static class RdsLicensingProbe
{
    private const string Namespace = @"root\cimv2\TerminalServices";
    private const string PolicyKeyPath = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    // Runs inside the 5 s server section budget of the sessions section, next to the WTS enumeration.
    private static readonly TimeSpan WmiTimeout = TimeSpan.FromSeconds(2);

    public static async Task<RdsLicensingInfo> ReadAsync(CancellationToken ct)
    {
        try
        {
            return await Task.Run(Read, CancellationToken.None).WaitAsync(WmiTimeout, ct).ConfigureAwait(false);
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

    private static RdsLicensingInfo Read()
    {
        var options = new ConnectionOptions { Timeout = WmiTimeout };
        var scope = new ManagementScope(Namespace, options);
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(
            scope,
            new ObjectQuery("SELECT * FROM Win32_TerminalServiceSetting"),
            new System.Management.EnumerationOptions { Timeout = WmiTimeout, ReturnImmediately = false });
        using var results = searcher.Get();
        foreach (ManagementObject setting in results)
        {
            using (setting)
            {
                var rdsh = Convert.ToInt32(setting["TerminalServerMode"]) == 1;
                if (!rdsh)
                    return RdsLicensingInfo.NotApplicable;

                var mode = MapLicensingMode(setting["LicensingType"] is null ? null : Convert.ToInt32(setting["LicensingType"]));
                return new RdsLicensingInfo("ok", true, mode, LicenseServerConfigured(setting), GraceDaysLeft(setting));
            }
        }

        return RdsLicensingInfo.Unavailable;
    }

    // Win32_TerminalServiceSetting.LicensingType: 2 = per device, 4 = per user, 5 = not configured.
    internal static string MapLicensingMode(int? licensingType) => licensingType switch
    {
        2 => "per_device",
        4 => "per_user",
        null or 0 or 5 => "not_configured",
        _ => "unknown",
    };

    private static bool? LicenseServerConfigured(ManagementObject setting)
    {
        try
        {
            using var output = setting.InvokeMethod("GetSpecifiedLicenseServerList", null, null);
            if (output?["SpecifiedLSList"] is string[] list && list.Any(s => !string.IsNullOrWhiteSpace(s)))
                return true;
        }
        catch (ManagementException)
        {
            // Fall through to the policy value.
        }

        using var key = Registry.LocalMachine.OpenSubKey(PolicyKeyPath);
        return key?.GetValue("LicenseServers") is string servers && !string.IsNullOrWhiteSpace(servers);
    }

    private static int? GraceDaysLeft(ManagementObject setting)
    {
        try
        {
            using var output = setting.InvokeMethod("GetGracePeriodDays", null, null);
            return output?["DaysLeft"] is { } days ? Math.Max(0, Convert.ToInt32(days)) : null;
        }
        catch (ManagementException)
        {
            return null;
        }
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
