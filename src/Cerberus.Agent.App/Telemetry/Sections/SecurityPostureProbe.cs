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
/// The snapshot path never calls this inline; <see cref="SecurityPostureCache"/> runs it in the background.
/// </summary>
internal static class SecurityPostureProbe
{
    private const string DefenderNamespace = @"root\Microsoft\Windows\Defender";
    private const string CimV2Namespace = @"root\cimv2";
    private const string LanmanParametersKey = @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
    private const int WbemInvalidNamespace = unchecked((int)0x8004100E);
    private const int WbemInvalidClass = unchecked((int)0x80041010);

    private static readonly string[] DefenderStatusProperties =
        ["AMServiceEnabled", "RealTimeProtectionEnabled", "AntivirusSignatureLastUpdated", "QuickScanEndTime", "FullScanEndTime", "AMRunningMode"];

    private static readonly string[] ThreatProperties = ["IsActive"];
    private static readonly string[] InstallStateProperties = ["InstallState"];

    internal static readonly object Unavailable = new { status = "unavailable" };

    /// <summary>One WMI query: the requested properties of every returned row (null for a property that cannot be read).</summary>
    internal delegate IReadOnlyList<IReadOnlyDictionary<string, object?>> WmiQuery(string wmiNamespace, string query, IReadOnlyList<string> properties);

    // Direct, blocking read (no cache).
    internal static IReadOnlyDictionary<string, object?> Read(CancellationToken ct) => new Dictionary<string, object?>
    {
        ["defender_av"] = Isolate("defender_av", ct, token => ReadDefender(ComWmi.Query, token)),
        ["smb1"] = Isolate("smb1", ct, token => ReadSmb1(ComWmi.Query, ReadSmb1Value, token)),
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
            return Unavailable;
        }
    }

    // Threat class: MSFT_MpThreat.IsActive (what Get-MpThreat reports) is a ready boolean per threat. MSFT_MpThreatDetection
    // is the per-detection history and only exposes numeric status ids that differ between Defender versions.
    // A missing namespace/class on the status query means Defender is not installed (not_applicable); a missing threat
    // class only leaves active_threats null.
    internal static object ReadDefender(WmiQuery query, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        IReadOnlyList<IReadOnlyDictionary<string, object?>> rows;
        try
        {
            rows = query(DefenderNamespace,
                "SELECT AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime, AMRunningMode FROM MSFT_MpComputerStatus",
                DefenderStatusProperties);
        }
        catch (COMException ex) when (IsNamespaceOrClassMissing(ex.HResult))
        {
            return DefenderNotApplicable;
        }

        if (rows.Count == 0 || MapDefenderStatus(Get(rows[0], "AMRunningMode") as string) != "ok")
            return DefenderNotApplicable;
        var row = rows[0];

        ct.ThrowIfCancellationRequested();
        int? active = null;
        try
        {
            active = query(DefenderNamespace, "SELECT IsActive FROM MSFT_MpThreat", ThreatProperties)
                .Count(static r => Get(r, "IsActive") is true);
        }
        catch (COMException ex) when (IsNamespaceOrClassMissing(ex.HResult))
        {
        }

        return new
        {
            status = "ok",
            am_service_enabled = Get(row, "AMServiceEnabled") as bool?,
            real_time_protection = Get(row, "RealTimeProtectionEnabled") as bool?,
            signature_updated_utc = ServerFactText.UtcOrNull(ParseDmtf(Get(row, "AntivirusSignatureLastUpdated"))),
            last_quick_scan_utc = ServerFactText.UtcOrNull(ParseDmtf(Get(row, "QuickScanEndTime"))),
            last_full_scan_utc = ServerFactText.UtcOrNull(ParseDmtf(Get(row, "FullScanEndTime"))),
            active_threats = active,
        };
    }

    internal static object? ReadSmb1Value()
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hklm.OpenSubKey(LanmanParametersKey, writable: false);
        return key?.GetValue("SMB1");
    }

    // Registry value first. Without it, the server component feature decides; the parent feature is only a fallback when
    // the child row is missing. No row at all is unknown, never a safe-looking false.
    internal static object ReadSmb1(WmiQuery query, Func<object?> registryValue, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (MapSmb1Value(registryValue()) is { } configured)
            return new { status = "ok", server_enabled = configured };

        foreach (var feature in new[] { "SMB1Protocol-Server", "SMB1Protocol" })
        {
            ct.ThrowIfCancellationRequested();
            var rows = query(CimV2Namespace, $"SELECT InstallState FROM Win32_OptionalFeature WHERE Name = '{feature}'", InstallStateProperties);
            if (rows.Count > 0 && Get(rows[0], "InstallState") is { } state)
                return new { status = "ok", server_enabled = (bool?)MapOptionalFeatureState(state) };
        }

        return new { status = "unavailable", server_enabled = (bool?)null };
    }

    private static object? Get(IReadOnlyDictionary<string, object?> row, string name) => row.TryGetValue(name, out var v) ? v : null;

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

    // Win32_OptionalFeature.InstallState (only called when a row exists): 1 = enabled; 2 = disabled, 3 = absent.
    internal static bool MapOptionalFeatureState(object? installState) => installState is 1 or 1u or (short)1;
}

/// <summary>Late-bound WMI through the in-box scripting COM API. Blocking; callers run it on a background thread.</summary>
internal static class ComWmi
{
    private const int WbemFlagReturnImmediately = 0x10;

    internal static IReadOnlyList<IReadOnlyDictionary<string, object?>> Query(string wmiNamespace, string query, IReadOnlyList<string> properties)
    {
        var result = new List<IReadOnlyDictionary<string, object?>>();
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
                    var values = new Dictionary<string, object?>(StringComparer.Ordinal);
                    foreach (var name in properties)
                        values[name] = Prop(row, name);
                    result.Add(values);
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

        return result;
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

internal sealed class WmiSecurityPostureReader : ISecurityPostureReader
{
    public object ReadDefender(CancellationToken ct) => SecurityPostureProbe.ReadDefender(ComWmi.Query, ct);

    public object ReadSmb1(CancellationToken ct) => SecurityPostureProbe.ReadSmb1(ComWmi.Query, SecurityPostureProbe.ReadSmb1Value, ct);
}
