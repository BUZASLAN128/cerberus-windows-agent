using System.Globalization;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>Installed software from the machine Uninstall keys. Uninstall strings and install paths are never read.</summary>
internal sealed class SoftwareTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    internal const int MaxSoftware = 500;
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    internal sealed record RawSoftware(string? Name, string? Version, string? Publisher, string? InstallDate, string Arch);

    public string SectionName => "software";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
        => ValueTask.FromResult(Build(Read(ct)));

    internal static object Build(IEnumerable<RawSoftware> raw)
    {
        var software = raw
            .Select(s => new
            {
                name = ServerFactText.Clean(s.Name, 128),
                version = ServerFactText.CleanOrNull(s.Version, 64),
                publisher = ServerFactText.CleanOrNull(s.Publisher, 128),
                installed_on = ParseInstallDate(s.InstallDate),
                arch = s.Arch,
            })
            .Where(s => s.name.Length > 0)
            .Distinct()
            .OrderBy(s => s.name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(s => s.name, StringComparer.Ordinal)
            .ThenBy(s => s.version, StringComparer.OrdinalIgnoreCase)
            .ThenBy(s => s.arch, StringComparer.Ordinal)
            .ThenBy(s => s.publisher, StringComparer.Ordinal)
            .ThenBy(s => s.installed_on, StringComparer.Ordinal)
            .ToArray();

        return new
        {
            status = "ok",
            software_count = software.Length,
            truncated = software.Length > MaxSoftware,
            software = software.Take(MaxSoftware).ToArray(),
        };
    }

    internal static string? ParseInstallDate(string? value)
        => value is { Length: 8 } && DateTime.TryParseExact(value, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date)
            ? date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            : null;

    internal static bool IsUpdateEntry(string keyName, string? releaseType, bool hasParent)
        => hasParent
           || keyName.StartsWith("KB", StringComparison.OrdinalIgnoreCase)
           || releaseType is not null && (
               releaseType.Contains("Update", StringComparison.OrdinalIgnoreCase)
               || releaseType.Contains("Hotfix", StringComparison.OrdinalIgnoreCase)
               || releaseType.Contains("Service Pack", StringComparison.OrdinalIgnoreCase));

    private static List<RawSoftware> Read(CancellationToken ct)
    {
        var result = new List<RawSoftware>();
        ReadView(RegistryView.Registry64, "x64", ct, result);
        ReadView(RegistryView.Registry32, "x86", ct, result);
        return result;
    }

    private static void ReadView(RegistryView view, string arch, CancellationToken ct, List<RawSoftware> result)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var root = baseKey.OpenSubKey(UninstallPath);
            if (root is null)
                return;

            foreach (var name in root.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var key = root.OpenSubKey(name);
                if (key is null)
                    continue;

                var displayName = key.GetValue("DisplayName") as string;
                if (string.IsNullOrWhiteSpace(displayName)
                    || key.GetValue("SystemComponent") is int and 1
                    || IsUpdateEntry(name, key.GetValue("ReleaseType") as string, key.GetValue("ParentKeyName") is not null))
                    continue;

                result.Add(new RawSoftware(
                    displayName,
                    key.GetValue("DisplayVersion") as string,
                    key.GetValue("Publisher") as string,
                    key.GetValue("InstallDate")?.ToString(),
                    arch));
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
        {
        }
    }
}
