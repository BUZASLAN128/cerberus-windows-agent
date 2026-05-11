using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class OsTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "os";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var version = ReadWindowsVersion();

        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            platform = Environment.OSVersion.Platform.ToString(),
            version = version.DisplayName,
            raw_version = Environment.OSVersion.VersionString,
            product_name = version.ProductName,
            edition_id = version.EditionId,
            display_version = version.DisplayVersion,
            build_number = version.BuildNumber,
            ubr = version.UpdateBuildRevision,
            architecture = RuntimeInformation.OSArchitecture.ToString(),
            process_architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            is_64_bit = Environment.Is64BitOperatingSystem,
        });
    }

    private static WindowsVersionInfo ReadWindowsVersion()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new WindowsVersionInfo(Environment.OSVersion.VersionString, null, null, null, null);
        }

        using var key = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        );
        var productName = ReadRegistryString(key, "ProductName");
        var editionId = ReadRegistryString(key, "EditionID");
        var displayVersion = ReadRegistryString(key, "DisplayVersion")
            ?? ReadRegistryString(key, "ReleaseId");
        var buildNumber = ReadRegistryString(key, "CurrentBuildNumber");
        var ubr = ReadRegistryString(key, "UBR");
        var displayName = BuildDisplayName(productName, editionId, displayVersion, buildNumber);

        return new WindowsVersionInfo(displayName, productName, editionId, displayVersion, buildNumber, ubr);
    }

    private static string? ReadRegistryString(RegistryKey? key, string name)
    {
        var value = key?.GetValue(name);
        return value is null ? null : Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string BuildDisplayName(
        string? productName,
        string? editionId,
        string? displayVersion,
        string? buildNumber)
    {
        var name = string.IsNullOrWhiteSpace(productName) ? "Windows" : productName.Trim();
        if (int.TryParse(buildNumber, out var build) && build >= 22000)
        {
            name = name.Replace("Windows 10", "Windows 11", StringComparison.OrdinalIgnoreCase);
            if (!name.Contains("Windows 11", StringComparison.OrdinalIgnoreCase))
            {
                name = $"Windows 11 {editionId}".Trim();
            }
        }

        var suffixParts = new List<string>();
        if (!string.IsNullOrWhiteSpace(displayVersion))
        {
            suffixParts.Add(displayVersion.Trim());
        }

        if (!string.IsNullOrWhiteSpace(buildNumber))
        {
            suffixParts.Add($"build {buildNumber.Trim()}");
        }

        return suffixParts.Count == 0 ? name : $"{name} ({string.Join(", ", suffixParts)})";
    }

    private sealed record WindowsVersionInfo(
        string DisplayName,
        string? ProductName,
        string? EditionId,
        string? DisplayVersion,
        string? BuildNumber,
        string? UpdateBuildRevision = null);
}
