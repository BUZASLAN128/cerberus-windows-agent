using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public sealed record BootstrapDescriptorEnvelope(
    [property: JsonPropertyName("payload")] BootstrapDescriptor Payload,
    [property: JsonPropertyName("signature")] string Signature);

public sealed record BootstrapDescriptor(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("descriptor_id")] string DescriptorId,
    [property: JsonPropertyName("issuer")] string Issuer,
    [property: JsonPropertyName("audience")] string Audience,
    [property: JsonPropertyName("bootstrap_api_base_url")] string BootstrapApiBaseUrl,
    [property: JsonPropertyName("telemetry_base_url")] string? TelemetryBaseUrl,
    [property: JsonPropertyName("config_version")] string? ConfigVersion,
    [property: JsonPropertyName("issued_at_utc")] string? IssuedAtUtc,
    [property: JsonPropertyName("expires_at_utc")] string ExpiresAtUtc);

public sealed class BootstrapDescriptorClient
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;

    public BootstrapDescriptorClient(HttpClient http)
    {
        _http = http;
    }

    public async Task<(BootstrapDescriptorEnvelope Envelope, string Raw)> FetchAsync(Uri descriptorUri, CancellationToken ct)
    {
        using var resp = await _http.GetAsync(descriptorUri, ct).ConfigureAwait(false);
        var raw = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Bootstrap descriptor fetch failed ({(int)resp.StatusCode}).");

        var parsed = JsonSerializer.Deserialize<BootstrapDescriptorEnvelope>(raw, JsonOpts);
        if (parsed?.Payload is null || string.IsNullOrWhiteSpace(parsed.Signature))
            throw new InvalidOperationException("Bootstrap descriptor missing payload/signature.");
        BootstrapDescriptorValidator.Validate(parsed.Payload);
        return (parsed, raw);
    }
}

public static class BootstrapDescriptorValidator
{
    public static void Validate(BootstrapDescriptor descriptor)
    {
        if (!string.Equals(descriptor.SchemaVersion, "agent.bootstrap.v1", StringComparison.Ordinal))
            throw new InvalidOperationException("Unsupported bootstrap descriptor schema.");
        if (string.IsNullOrWhiteSpace(descriptor.BootstrapApiBaseUrl))
            throw new InvalidOperationException("Bootstrap descriptor missing API base URL.");
        if (!Uri.TryCreate(descriptor.BootstrapApiBaseUrl, UriKind.Absolute, out _))
            throw new InvalidOperationException("Bootstrap descriptor API base URL is invalid.");
        if (string.IsNullOrWhiteSpace(descriptor.ExpiresAtUtc) ||
            !DateTimeOffset.TryParse(descriptor.ExpiresAtUtc, out var expiresAt))
            throw new InvalidOperationException("Bootstrap descriptor expiry is invalid.");
        if (expiresAt <= DateTimeOffset.UtcNow)
            throw new InvalidOperationException("Bootstrap descriptor expired.");
    }

    public static Uri ResolveDescriptorUri(Uri issuerBase, string? explicitDescriptorUrl)
    {
        if (!string.IsNullOrWhiteSpace(explicitDescriptorUrl))
        {
            if (!Uri.TryCreate(explicitDescriptorUrl.Trim(), UriKind.Absolute, out var explicitUri))
                throw new InvalidOperationException("Bootstrap descriptor URL is invalid.");
            return explicitUri;
        }

        var baseText = issuerBase.ToString().TrimEnd('/');
        return new Uri($"{baseText}/.well-known/cerberus-agent-bootstrap.json", UriKind.Absolute);
    }
}
