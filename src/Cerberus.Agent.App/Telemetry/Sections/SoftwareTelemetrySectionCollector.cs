using System.Globalization;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>Installed software from the machine Uninstall keys and the loaded user hives. Uninstall strings and install paths are never read.</summary>
internal sealed class SoftwareTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    internal const int MaxSoftware = 500;
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    internal sealed record RawSoftware(string? Name, string? Version, string? Publisher, string? InstallDate, string Arch, string Scope = "machine", string? UserSid = null);

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
                scope = s.Scope,
                user_sid = s.Scope == "user" ? ServerFactText.CleanOrNull(s.UserSid, 128) : null,
            })
            .Where(s => s.name.Length > 0)
            .Distinct()
            .OrderBy(s => s.name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(s => s.name, StringComparer.Ordinal)
            .ThenBy(s => s.version, StringComparer.OrdinalIgnoreCase)
            .ThenBy(s => s.arch, StringComparer.Ordinal)
            .ThenBy(s => s.publisher, StringComparer.Ordinal)
            .ThenBy(s => s.installed_on, StringComparer.Ordinal)
            .ThenBy(s => s.scope, StringComparer.Ordinal)
            .ThenBy(s => s.user_sid, StringComparer.Ordinal)
            .ToArray();

        // Cap: machine entries first, user entries fill what is left. Output keeps the sorted order above.
        var machineLeft = MaxSoftware;
        var userLeft = Math.Max(0, MaxSoftware - software.Count(s => s.scope != "user"));
        var kept = software.Where(entry =>
        {
            if (entry.scope == "user")
                return userLeft > 0 && userLeft-- > 0;
            return machineLeft > 0 && machineLeft-- > 0;
        }).ToArray();

        return new
        {
            status = "ok",
            software_count = software.Length,
            truncated = software.Length > MaxSoftware,
            software = kept,
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

    /// <summary>Loaded interactive-user hives only: domain/local (S-1-5-21-) and Microsoft Entra (S-1-12-1-) account SIDs, not the per-user _Classes hives.</summary>
    internal static bool IsUserHiveSid(string name)
        => (name.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("S-1-12-1-", StringComparison.OrdinalIgnoreCase))
           && !name.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase);

    private static List<RawSoftware> Read(CancellationToken ct)
    {
        var result = new List<RawSoftware>();
        ReadView(RegistryHive.LocalMachine, RegistryView.Registry64, UninstallPath, "x64", "machine", null, ct, result);
        ReadView(RegistryHive.LocalMachine, RegistryView.Registry32, UninstallPath, "x86", "machine", null, ct, result);
        ReadUserHives(ct, result);
        return result;
    }

    private static void ReadUserHives(CancellationToken ct, List<RawSoftware> result)
    {
        string[] sids;
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            sids = users.GetSubKeyNames().Where(IsUserHiveSid).ToArray();
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
        {
            return;
        }

        foreach (var sid in sids)
        {
            ct.ThrowIfCancellationRequested();
            var path = sid + @"\Software\Microsoft\Windows\CurrentVersion\Uninstall";
            // HKU\<SID>\Software\...\Uninstall is not WOW64-redirected: one read, so arch carries the view ("x64"), not the app bitness.
            ReadView(RegistryHive.Users, RegistryView.Registry64, path, "x64", "user", sid, ct, result);
        }
    }

    private static void ReadView(RegistryHive hive, RegistryView view, string path, string arch, string scope, string? userSid, CancellationToken ct, List<RawSoftware> result)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var root = baseKey.OpenSubKey(path);
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
                    arch,
                    scope,
                    userSid));
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
        {
        }
    }
}
