using System.Text.RegularExpressions;

namespace Cerberus.Agent.Observability;

public static class Sanitizer
{
    private static readonly Regex SecretLike = new(
        "(token|secret|password|authorization|private[_-]?key|api[_-]?key|client[_-]?secret|refresh[_-]?token|access[_-]?token)\\s*[:=]\\s*[^\\s]+",
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

    private static readonly Regex TailscaleKeyLike = new(
        // tskey-auth-..., tskey-client-...
        "tskey-(auth|client)-[A-Za-z0-9_-]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex OpenAiKeyLike = new(
        "\\b(sk|pk)-[A-Za-z0-9][A-Za-z0-9_-]{16,}\\b",
        RegexOptions.Compiled);

    private static readonly Regex LongBase64SecretLike = new(
        "\\b(?:[A-Za-z0-9+/]{48,}={0,2}|[A-Za-z0-9_-]{48,})\\b",
        RegexOptions.Compiled);

    public static string Redact(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return value ?? string.Empty;
        var v = value;
        v = SecretLike.Replace(v, "$1=[REDACTED]");
        v = HeadscaleKeyLike.Replace(v, "hskey-$1-[REDACTED]");
        v = TailscaleKeyLike.Replace(v, "tskey-$1-[REDACTED]");
        v = JwtLike.Replace(v, "[REDACTED_JWT]");
        v = OpenAiKeyLike.Replace(v, "[REDACTED_API_KEY]");
        v = LongBase64SecretLike.Replace(v, "[REDACTED_SECRET]");
        return v;
    }
}
