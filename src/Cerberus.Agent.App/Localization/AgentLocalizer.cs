using System.Globalization;
using System.Reflection;
using System.Resources;
using Microsoft.Win32;

namespace Cerberus.Agent.App.Localization;

internal static class AgentLocalizer
{
    public const string DefaultCultureName = "en-US";
    public const string TurkishCultureName = "tr-TR";
    public const string LanguageEnvVar = "CERBERUS_LANGUAGE";

    private static readonly string[] SupportedCultures = [DefaultCultureName, TurkishCultureName];
    private static readonly string[] ResourceBaseNames =
    [
        "Cerberus.Agent.App.Localization.AgentStrings",
        "Cerberus.Agent.Runtime.Localization.AgentStrings",
    ];

    public static CultureInfo ResolveCulture(string? requested = null)
    {
        var candidates = new[]
        {
            requested,
            Environment.GetEnvironmentVariable(LanguageEnvVar),
            ReadInstallerLanguage(),
            CultureInfo.CurrentUICulture.Name,
            CultureInfo.CurrentUICulture.TwoLetterISOLanguageName,
            DefaultCultureName,
        };

        foreach (var candidate in candidates)
        {
            var normalized = NormalizeCulture(candidate);
            if (normalized is not null)
                return CultureInfo.GetCultureInfo(normalized);
        }

        return CultureInfo.GetCultureInfo(DefaultCultureName);
    }

    public static void ApplyThreadCulture(string? requested = null)
    {
        var culture = ResolveCulture(requested);
        CultureInfo.CurrentUICulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
    }

    public static string Get(string key, CultureInfo? culture = null)
    {
        culture ??= ResolveCulture();
        foreach (var baseName in ResourceBaseNames)
        {
            try
            {
                var manager = new ResourceManager(baseName, typeof(AgentLocalizer).Assembly);
                var value = manager.GetString(key, culture)
                            ?? manager.GetString(key, CultureInfo.GetCultureInfo(DefaultCultureName));
                if (!string.IsNullOrWhiteSpace(value))
                    return value;
            }
            catch (MissingManifestResourceException)
            {
                // The same source file is linked into more than one assembly; try the next base name.
            }
        }

        return key;
    }

    public static string Format(string key, params object[] args)
        => string.Format(CultureInfo.CurrentUICulture, Get(key), args);

    internal static string? NormalizeCulture(string? requested)
    {
        if (string.IsNullOrWhiteSpace(requested))
            return null;

        var value = requested.Trim();
        if (string.Equals(value, "auto", StringComparison.OrdinalIgnoreCase))
            return null;
        if (string.Equals(value, "tr", StringComparison.OrdinalIgnoreCase))
            return TurkishCultureName;
        if (string.Equals(value, "en", StringComparison.OrdinalIgnoreCase))
            return DefaultCultureName;

        foreach (var supported in SupportedCultures)
        {
            if (string.Equals(value, supported, StringComparison.OrdinalIgnoreCase))
                return supported;
        }

        try
        {
            var culture = CultureInfo.GetCultureInfo(value);
            foreach (var supported in SupportedCultures)
            {
                if (string.Equals(culture.Name, supported, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(culture.TwoLetterISOLanguageName, supported[..2], StringComparison.OrdinalIgnoreCase))
                    return supported;
            }
        }
        catch (CultureNotFoundException)
        {
            return null;
        }

        return null;
    }

    private static string? ReadInstallerLanguage()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Cerberus\WindowsAgent");
            return key?.GetValue("language")?.ToString();
        }
        catch
        {
            return null;
        }
    }
}
