using System.Text;

namespace Cerberus.Agent.App.Telemetry;

/// <summary>Text rules shared by the server-profile fact sections (contract section e).</summary>
internal static class ServerFactText
{
    /// <summary>Drops control characters, trims, and cuts to <paramref name="maxScalars"/> Unicode scalars.</summary>
    public static string Clean(string? value, int maxScalars)
    {
        if (string.IsNullOrEmpty(value) || maxScalars <= 0)
            return string.Empty;

        var builder = new StringBuilder(Math.Min(value.Length, maxScalars * 2));
        var scalars = 0;
        foreach (var rune in value.EnumerateRunes())
        {
            if (Rune.IsControl(rune))
                continue;
            if (scalars == maxScalars)
                break;
            builder.Append(rune.ToString());
            scalars++;
        }

        return builder.ToString().Trim();
    }

    public static string? CleanOrNull(string? value, int maxScalars)
    {
        var cleaned = Clean(value, maxScalars);
        return cleaned.Length == 0 ? null : cleaned;
    }

    public static string Utc(DateTimeOffset value)
        => value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    public static string? UtcOrNull(DateTimeOffset? value) => value is null ? null : Utc(value.Value);

    public static object Unavailable(string section, string reason) => new
    {
        status = "unavailable",
        section,
        reason,
    };
}
