using System.Globalization;
using System.Runtime.InteropServices;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry;

/// <summary>
/// Owner-requested posture facts for the security section: Microsoft Defender state and the SMB1 server flag.
/// WMI is reached through the in-box scripting COM API (late bound, like the Windows Update probe), so the App
/// project needs no extra package. Each key degrades on its own; one failure never drops the other key.
/// </summary>
internal static class SecurityPostureProbe
{
    private const string DefenderNamespace = @"root\Microsoft\Windows\Defender";
    private const string CimV2Namespace = @"root\cimv2";
    private const string LanmanParametersKey = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const int WbemInvalidNamespace = unchecked((int)0x8004100E);
    private const int WbemInvalidClass = unchecked((int)0x80041010);
    private const int WbemFlagReturnImmediately = 0x10;
    private static readonly TimeSpan WmiTimeout = TimeSpan.FromSeconds(5);

    internal static IReadOnlyDictionary<string, object?> Read(CancellationToken ct) => new Dictionary<string, object?>
    {
        ["defender_av"] = Isolate("defender_av", ct, ReadDefender),
        ["smb1"] = Isolate("smb1", ct, ReadSmb1),
    };

    private static object Isolate(string key, CancellationToken ct, Func<CancellationToken, object> read)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            return read(ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            TelemetrySectionCapture.Log?.Warn(
                $"Telemetry section security {key} {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)} at={ExceptionSite.FirstFrame(ex)}");
            return new { status = "unavailable" };
        }
    }

    // Threat class: MSFT_MpThreat.IsActive (what Get-MpThreat reports) is a ready boolean per threat. MSFT_MpThreatDetection
    // is the per-detection history and only exposes numeric status ids that differ between Defender versions.
    private static object ReadDefender(CancellationToken ct)
    {
        try
        {
            return RunBounded(() => QueryDefender(), ct);
        }
        catch (COMException ex) when (IsNamespaceOrClassMissing(ex.HResult))
        {
            return DefenderNotApplicable;
        }
    }

    private static object QueryDefender()
    {
        var status = QueryFirst(DefenderNamespace,
            "SELECT AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime, AMRunningMode FROM MSFT_MpComputerStatus",
            static row => new DefenderRow(
                Prop(row, "AMServiceEnabled") as bool?,
                Prop(row, "RealTimeProtectionEnabled") as bool?,
                ParseDmtf(Prop(row, "AntivirusSignatureLastUpdated")),
                ParseDmtf(Prop(row, "QuickScanEndTime")),
                ParseDmtf(Prop(row, "FullScanEndTime")),
                Prop(row, "AMRunningMode") as string));
        if (status is null)
            return DefenderNotApplicable;
        if (MapDefenderStatus(status.RunningMode) != "ok")
            return DefenderNotApplicable;

        var active = CountActiveThreats();
        return new
        {
            status = "ok",
            am_service_enabled = status.AmServiceEnabled,
            real_time_protection = status.RealTimeProtection,
            signature_updated_utc = ServerFactText.UtcOrNull(status.SignatureUpdated),
            last_quick_scan_utc = ServerFactText.UtcOrNull(status.QuickScan),
            last_full_scan_utc = ServerFactText.UtcOrNull(status.FullScan),
            active_threats = active,
        };
    }

    private static int CountActiveThreats()
    {
        var count = 0;
        ForEachRow(DefenderNamespace, "SELECT IsActive FROM MSFT_MpThreat", row =>
        {
            if (Prop(row, "IsActive") is true)
                count++;
        });
        return count;
    }

    private static object ReadSmb1(CancellationToken ct)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.OpenSubKey(LanmanParametersKey, writable: false);
        var configured = MapSmb1Value(key?.GetValue("SMB1"));
        if (configured is { } enabled)
            return new { status = "ok", server_enabled = enabled };

        var feature = RunBounded(() => QueryFirst(CimV2Namespace,
            "SELECT InstallState FROM Win32_OptionalFeature WHERE Name = 'SMB1Protocol'",
            static row => Prop(row, "InstallState")), ct);
        return new { status = "ok", server_enabled = MapOptionalFeatureState(feature) };
    }

    private static readonly object DefenderNotApplicable = new
    {
        status = "not_applicable",
        am_service_enabled = (bool?)null,
        real_time_protection = (bool?)null,
        signature_updated_utc = (string?)null,
        last_quick_scan_utc = (string?)null,
        last_full_scan_utc = (string?)null,
        active_threats = (int?)null,
    };

    // AMRunningMode: only Normal (or an OS that does not report it) is Defender's own posture. Passive, SxS Passive,
    // EDR Block and "Not running" (what Defender reports while a third-party antivirus is registered, with empty fields)
    // mean another product owns real-time protection, so the Defender fields do not describe the machine.
    internal static string MapDefenderStatus(string? runningMode)
    {
        var mode = runningMode?.Trim();
        if (string.IsNullOrEmpty(mode)
            || mode.Equals("Normal", StringComparison.OrdinalIgnoreCase))
            return "ok";
        return "not_applicable";
    }

    // WBEM_E_INVALID_NAMESPACE / WBEM_E_INVALID_CLASS: Defender is not installed or its provider is not registered.
    internal static bool IsNamespaceOrClassMissing(int hresult) => hresult is WbemInvalidNamespace or WbemInvalidClass;

    // CIM datetime "yyyyMMddHHmmss.ffffff+UUU" (UUU = minutes east of UTC). Null for empty, malformed, year 1601 or earlier.
    internal static DateTimeOffset? ParseDmtf(object? value)
    {
        if (value is DateTime dt)
            return dt.Year <= 1601 ? null : new DateTimeOffset(dt.ToUniversalTime());
        if (value is not string text || text.Length < 25 || text[14] != '.')
            return null;
        if (!int.TryParse(text.AsSpan(0, 4), NumberStyles.None, CultureInfo.InvariantCulture, out var year) || year <= 1601)
            return null;
        if (!TryPart(text, 4, 2, out var month) || !TryPart(text, 6, 2, out var day)
            || !TryPart(text, 8, 2, out var hour) || !TryPart(text, 10, 2, out var minute) || !TryPart(text, 12, 2, out var second)
            || !TryPart(text, 22, 3, out var offsetMinutes) || text[21] is not ('+' or '-'))
            return null;
        try
        {
            var local = new DateTime(year, month, day, hour, minute, second, DateTimeKind.Unspecified);
            var offset = TimeSpan.FromMinutes(text[21] == '-' ? -offsetMinutes : offsetMinutes);
            return new DateTimeOffset(local, offset).ToUniversalTime();
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static bool TryPart(string text, int start, int length, out int value)
        => int.TryParse(text.AsSpan(start, length), NumberStyles.None, CultureInfo.InvariantCulture, out value);

    // LanmanServer SMB1: 0 = disabled, 1 = enabled; absent or any other value = not configured (null).
    internal static bool? MapSmb1Value(object? value) => value is int v ? v switch { 0 => false, 1 => true, _ => null } : null;

    // Win32_OptionalFeature.InstallState: 1 = enabled; 2 = disabled, 3 = absent. No row means the feature is absent.
    internal static bool MapOptionalFeatureState(object? installState) => installState is 1 or 1u or (short)1;

    private sealed record DefenderRow(
        bool? AmServiceEnabled, bool? RealTimeProtection, DateTimeOffset? SignatureUpdated,
        DateTimeOffset? QuickScan, DateTimeOffset? FullScan, string? RunningMode);

    // The scripting COM call has no cancellation of its own; an abandoned query finishes on the pool thread and is dropped.
    private static T RunBounded<T>(Func<T> work, CancellationToken ct)
    {
        var task = Task.Run(work, CancellationToken.None);
        if (!task.Wait(WmiTimeout, ct))
            throw new TimeoutException("WMI query timed out.");
        return task.GetAwaiter().GetResult();
    }

    private static T? QueryFirst<T>(string wmiNamespace, string query, Func<object, T> map)
    {
        T? result = default;
        var found = false;
        ForEachRow(wmiNamespace, query, row =>
        {
            if (found)
                return;
            result = map(row);
            found = true;
        });
        return result;
    }

    private static void ForEachRow(string wmiNamespace, string query, Action<object> onRow)
    {
        var locatorType = Type.GetTypeFromProgID("WbemScripting.SWbemLocator")
            ?? throw new PlatformNotSupportedException("WMI scripting API is not available.");
        object? locator = null;
        object? service = null;
        object? rows = null;
        try
        {
            locator = Activator.CreateInstance(locatorType)!;
            dynamic loc = locator;
            service = loc.ConnectServer(".", wmiNamespace);
            dynamic svc = service;
            rows = svc.ExecQuery(query, "WQL", WbemFlagReturnImmediately);
            foreach (var row in (System.Collections.IEnumerable)rows)
            {
                try
                {
                    onRow(row);
                }
                finally
                {
                    if (Marshal.IsComObject(row))
                        Marshal.FinalReleaseComObject(row);
                }
            }
        }
        finally
        {
            foreach (var com in new[] { rows, service, locator })
            {
                if (com is not null && Marshal.IsComObject(com))
                    Marshal.FinalReleaseComObject(com);
            }
        }
    }

    private static object? Prop(object row, string name)
    {
        dynamic obj = row;
        try
        {
            return obj.Properties_.Item(name).Value;
        }
        catch (COMException)
        {
            return null;
        }
    }
}
