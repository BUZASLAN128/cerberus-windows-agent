using System.Text.Json;

namespace Cerberus.Agent.Core;

/// <summary>Validates the untrusted discovery and notification fields before any wake-up connection is made.</summary>
public static class AgentWakeupProtocol
{
    public const string Capability = "agent.wakeup.v1";
    public const int MaxNotificationBytes = 256;

    /// <summary>Ignore missing or malformed discovery while preserving the normal HTTPS heartbeat.</summary>
    public static bool TryReadDiscovery(Uri backend, JsonElement? discovery, out Uri? endpoint)
    {
        endpoint = null;
        if (discovery is not { ValueKind: JsonValueKind.Object } objectValue)
            return false;
        var sawVersion = false;
        var sawPath = false;
        var version = 0;
        string? path = null;
        foreach (var property in objectValue.EnumerateObject())
        {
            if (property.NameEquals("version") && !sawVersion && property.Value.ValueKind == JsonValueKind.Number &&
                property.Value.TryGetInt32(out version))
                sawVersion = true;
            else if (property.NameEquals("path") && !sawPath && property.Value.ValueKind == JsonValueKind.String)
            {
                sawPath = true;
                path = property.Value.GetString();
            }
            else
                return false;
        }
        return sawVersion && sawPath && TryResolveEndpoint(backend, version, path, out endpoint);
    }

    /// <summary>Resolve an origin-relative path without allowing credentials to be sent to another authority.</summary>
    public static bool TryResolveEndpoint(Uri backend, int version, string? path, out Uri? endpoint)
    {
        endpoint = null;
        if (version != 1 || backend is null || !backend.IsAbsoluteUri ||
            backend.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(backend.UserInfo) ||
            string.IsNullOrEmpty(path) || path[0] != '/' || path.StartsWith("//", StringComparison.Ordinal))
            return false;

        // The endpoint uses plain path segments. Reject escapes and normalization ambiguities,
        // rather than allowing a signed path to differ from the path actually sent on the wire.
        foreach (var c in path)
            if (!(char.IsAsciiLetterOrDigit(c) || c is '/' or '-' or '_' or '.' or '~'))
                return false;
        if (path.Split('/').Any(segment => segment is "." or ".."))
            return false;

        var origin = new Uri(backend.GetLeftPart(UriPartial.Authority) + "/", UriKind.Absolute);
        if (!Uri.TryCreate(origin, path, out var resolved) ||
            !string.Equals(resolved.IdnHost, origin.IdnHost, StringComparison.OrdinalIgnoreCase) ||
            resolved.Port != origin.Port || resolved.Scheme != Uri.UriSchemeHttps)
            return false;
        endpoint = new UriBuilder(resolved) { Scheme = "wss" }.Uri;
        return true;
    }

    /// <summary>Accept only the bounded v1 hint, never a command or an authorization decision.</summary>
    public static bool IsCommandAvailable(ReadOnlyMemory<byte> message)
    {
        if (message.Length == 0 || message.Length > MaxNotificationBytes)
            return false;
        try
        {
            using var document = JsonDocument.Parse(message);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;
            var seenType = false;
            var seenVersion = false;
            foreach (var property in root.EnumerateObject())
            {
                if (property.NameEquals("type") && !seenType && property.Value.ValueKind == JsonValueKind.String &&
                    property.Value.GetString() == "command_available")
                    seenType = true;
                else if (property.NameEquals("version") && !seenVersion && property.Value.ValueKind == JsonValueKind.Number &&
                         property.Value.TryGetInt32(out var version) && version == 1)
                    seenVersion = true;
                else
                    return false;
            }
            return seenType && seenVersion;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
