using System.Text.RegularExpressions;

namespace Cerberus.Agent.Observability;

public static class Sanitizer
{
    private static readonly Regex SecretLike = new(
        "(token|secret|password|authorization|private[_-]?key)\\s*[:=]\\s*[^\\s]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex JwtLike = new(
        // JWTs (esp. Casdoor) typically start with "eyJ" (base64url of '{"').
        // Avoid matching dotted strings like IPs or "offline.tailscale.probe".
        "(Bearer\\s+)?eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HeadscaleKeyLike = new(
        // hskey-api-..., hskey-auth-...
        "hskey-(api|auth)-[A-Za-z0-9_-]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static string Redact(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return value ?? string.Empty;
        var v = value;
        v = SecretLike.Replace(v, "$1=[REDACTED]");
        v = HeadscaleKeyLike.Replace(v, "hskey-$1-[REDACTED]");
        v = JwtLike.Replace(v, "[REDACTED_JWT]");
        return v;
    }
}
