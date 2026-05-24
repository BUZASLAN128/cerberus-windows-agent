using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Cerberus.Agent.Observability;

public static class Sanitizer
{
    private static readonly string[] SensitiveNameFragments =
    [
        "token",
        "secret",
        "password",
        "authorization",
        "private_key",
        "private-key",
        "apikey",
        "api_key",
        "api-key",
        "client_secret",
        "client-secret",
        "refresh_token",
        "refresh-token",
        "access_token",
        "access-token",
        "authkey",
        "auth_key",
    ];

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
        if (!MayContainSecret(value))
            return value;

        var v = value;
        v = RedactStructuredJson(v);
        v = SecretLike.Replace(v, "$1=[REDACTED]");
        v = HeadscaleKeyLike.Replace(v, "hskey-$1-[REDACTED]");
        v = TailscaleKeyLike.Replace(v, "tskey-$1-[REDACTED]");
        v = JwtLike.Replace(v, "[REDACTED_JWT]");
        v = OpenAiKeyLike.Replace(v, "[REDACTED_API_KEY]");
        v = LongBase64SecretLike.Replace(v, "[REDACTED_SECRET]");
        return v;
    }

    private static bool MayContainSecret(string value)
    {
        foreach (var fragment in SensitiveNameFragments)
        {
            if (value.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return value.Contains("eyJ", StringComparison.Ordinal) ||
               value.Contains("hskey-", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("tskey-", StringComparison.OrdinalIgnoreCase) ||
               value.Contains("sk-", StringComparison.Ordinal) ||
               value.Contains("pk-", StringComparison.Ordinal) ||
               HasLongEncodedToken(value);
    }

    private static string RedactStructuredJson(string value)
    {
        var trimmed = value.TrimStart();
        if (!trimmed.StartsWith('{') && !trimmed.StartsWith('['))
            return value;

        try
        {
            var node = JsonNode.Parse(value);
            if (node is null)
                return value;
            RedactNode(node);
            return node.ToJsonString(new JsonSerializerOptions(JsonSerializerDefaults.Web));
        }
        catch (JsonException)
        {
            return value;
        }
    }

    private static void RedactNode(JsonNode node)
    {
        if (node is JsonObject obj)
        {
            foreach (var item in obj.ToArray())
            {
                if (IsSensitiveName(item.Key))
                {
                    obj[item.Key] = "[REDACTED]";
                    continue;
                }

                if (item.Value is not null)
                    RedactNode(item.Value);
            }
            return;
        }

        if (node is JsonArray array)
        {
            foreach (var item in array)
            {
                if (item is not null)
                    RedactNode(item);
            }
        }
    }

    private static bool IsSensitiveName(string name)
        => SensitiveNameFragments.Any(fragment =>
            name.Contains(fragment, StringComparison.OrdinalIgnoreCase));

    private static bool HasLongEncodedToken(string value)
    {
        var run = 0;
        foreach (var ch in value)
        {
            if (char.IsLetterOrDigit(ch) || ch is '+' or '/' or '_' or '-' or '=')
            {
                run++;
                if (run >= 48)
                    return true;
                continue;
            }

            run = 0;
        }

        return false;
    }
}
