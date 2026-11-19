using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

/// <summary>Explicit build-bound authority for the two enrolled development-test targets.</summary>
internal sealed record AgentUpdateLabPolicy(
    string SchemaVersion,
    string CampaignId,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset ExpiresAtUtc,
    AgentUpdateLabTarget[] Targets,
    string[] Versions,
    string BackendUrl,
    string SsoBaseUrl)
{
    internal const string MetadataName = "AgentUpdateLabPolicyB64";
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    internal static AgentUpdateLabPolicy? Parse(string? encoded, string channel, bool unsignedDev, bool server)
    {
        if (string.IsNullOrEmpty(encoded)) return null;
        if (channel != "dev" || !unsignedDev || !server)
            throw Denied();
        try
        {
            if (encoded.Length > 16384) throw Denied();
            var bytes = Convert.FromBase64String(encoded);
            using var document = JsonDocument.Parse(bytes);
            RequireUniqueProperties(document.RootElement);
            var policy = JsonSerializer.Deserialize<AgentUpdateLabPolicy>(bytes, Options) ?? throw Denied();
            policy.Validate();
            return policy;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentException)
        {
            throw new InvalidOperationException("Development update policy is invalid.", ex);
        }
    }

    internal AgentUpdateLabTarget RequireTarget(AgentIdentity identity, string keyFingerprint, DateTimeOffset now)
    {
        if (now < NotBeforeUtc || now >= ExpiresAtUtc) throw Denied();
        var target = Targets.SingleOrDefault(t => t.AgentId == identity.AgentId && t.TenantId == identity.TenantId &&
            FixedFingerprintEquals(t.KeyFingerprint, keyFingerprint));
        return target ?? throw Denied();
    }

    internal void RequireVersion(string version)
    {
        var release = version.Split('+', 2)[0];
        if (!Versions.Contains(release, StringComparer.Ordinal)) throw Denied();
    }

    internal void RequireSuccessor(string installedVersion, string targetVersion)
        => AgentUpdateCampaignTransition.RequireNext(Versions, installedVersion, targetVersion);

    private void Validate()
    {
        if (SchemaVersion != "agent.update.lab.v1" || !Guid.TryParseExact(CampaignId, "D", out _) ||
            NotBeforeUtc.Offset != TimeSpan.Zero || ExpiresAtUtc.Offset != TimeSpan.Zero ||
            ExpiresAtUtc <= NotBeforeUtc || ExpiresAtUtc - NotBeforeUtc > TimeSpan.FromHours(48) ||
            Targets is not { Length: 2 } || Versions is not { Length: 11 } ||
            !ValidBackendUri(BackendUrl) || !ValidBackendUri(SsoBaseUrl)) throw Denied();
        if (Targets.Any(t => t is null)) throw Denied();
        foreach (var target in Targets)
        {
            if (!ValidId(target.AgentId) || !ValidId(target.TenantId) || !ValidFingerprint(target.KeyFingerprint) ||
                !ValidFeedUri(target.ManifestUrl) || !ValidFeedUri(target.ArtifactPrefix) ||
                !target.ArtifactPrefix.EndsWith("/", StringComparison.Ordinal) ||
                !Version.TryParse(target.BootstrapSourceVersion, out var baseline) || baseline.Build < 0 || baseline.Revision != -1 ||
                baseline.ToString(3) != target.BootstrapSourceVersion || Versions.Contains(target.BootstrapSourceVersion!) ||
                !AgentUpdateManifestValidator.IsAllowedArtifactUri(new Uri(target.ManifestUrl), target.ArtifactPrefix)) throw Denied();
        }
        if (Targets.Select(t => t.AgentId).Distinct(StringComparer.Ordinal).Count() != 2 ||
            Targets.Select(t => t.KeyFingerprint).Distinct(StringComparer.Ordinal).Count() != 2 ||
            Targets.Select(t => t.ManifestUrl).Distinct(StringComparer.Ordinal).Count() != 2) throw Denied();
        Version? previous = null;
        foreach (var version in Versions)
        {
            if (!Version.TryParse(version, out var parsed) || parsed.Revision != -1 || parsed.Build < 0 ||
                parsed.ToString(3) != version || (previous is not null && parsed <= previous)) throw Denied();
            previous = parsed;
        }
    }

    private static bool ValidId(string? id)
        => id is { Length: > 0 and <= 128 } && id == id.Trim() && !id.Any(char.IsControl);

    private static bool ValidBackendUri(string? value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps && !uri.IsLoopback &&
            string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment);

    private static bool ValidFeedUri(string? value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps &&
            string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment) &&
            uri.AbsolutePath.StartsWith("/updates/devtest/", StringComparison.Ordinal);

    private static bool ValidFingerprint(string? value)
        => value is { Length: 71 } && value.StartsWith(AgentKeyFingerprint.Prefix, StringComparison.Ordinal) &&
            value[7..].All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool FixedFingerprintEquals(string expected, string supplied)
        => ValidFingerprint(supplied) && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(supplied));

    private static void RequireUniqueProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw Denied();
                RequireUniqueProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) RequireUniqueProperties(item);
    }

    private static InvalidOperationException Denied() => new("Development update policy is not authorized.");
}

internal sealed record AgentUpdateLabTarget(string AgentId, string TenantId, string KeyFingerprint,
    string ManifestUrl, string ArtifactPrefix, string? BootstrapSourceVersion = null);
