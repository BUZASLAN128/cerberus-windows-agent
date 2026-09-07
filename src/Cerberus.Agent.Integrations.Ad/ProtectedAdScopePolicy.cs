using System.Net;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Integrations.Ad;

public sealed record AdScopePolicyDocument(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("tenant_id")] string TenantId,
    [property: JsonPropertyName("agent_id")] string AgentId,
    [property: JsonPropertyName("scopes")] AdScope[] Scopes);

/// <summary>Only a locally installed, protected administrator policy can select AD targets. Missing policy disables AD.</summary>
public sealed class ProtectedAdScopePolicy
{
    public const string SchemaVersion = "agent.ad-scope-policy.v1";
    public static string PolicyPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CerberusAgent", "Privileged", "DirectoryUsers", "policy.json");
    private const int MaxPolicyBytes = 65536;

    public IReadOnlyList<AdScope> Load(AgentIdentity identity)
    {
        if (!AgentUpdateSecurity.IsLocalSystem()) throw new AdOperationDeniedException("ad_system_identity_required");
        var root = Path.GetDirectoryName(PolicyPath)!;
        // Loading does not create or repair administrative configuration, even when AD is disabled.
        AgentUpdateSecurity.ValidateProtectedPath(PolicyPath, root, allowMissing: true);
        if (!File.Exists(PolicyPath)) return Array.Empty<AdScope>();
        using var stream = new FileStream(PolicyPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 or > MaxPolicyBytes) throw new AdOperationDeniedException("ad_policy_invalid");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        return Decode(bytes, identity);
    }

    // Array overload permits the read-only setup validator to invoke the same parser from PowerShell.
    public static IReadOnlyList<AdScope> Decode(byte[] bytes, AgentIdentity identity) => Decode(bytes.AsSpan(), identity);

    public static IReadOnlyList<AdScope> Decode(ReadOnlySpan<byte> bytes, AgentIdentity identity)
    {
        if (bytes.Length is <= 0 or > MaxPolicyBytes) throw new AdOperationDeniedException("ad_policy_invalid");
        AdScopePolicyDocument? document;
        try { document = JsonSerializer.Deserialize<AdScopePolicyDocument>(bytes); }
        catch (JsonException) { throw new AdOperationDeniedException("ad_policy_invalid"); }
        if (document is null || document.SchemaVersion != SchemaVersion || document.TenantId != identity.TenantId ||
            document.AgentId != identity.AgentId || document.Scopes is null || document.Scopes.Length > 64)
            throw new AdOperationDeniedException("ad_policy_invalid");
        if (!document.Enabled) return Array.Empty<AdScope>();
        if (document.Scopes.Select(s => s?.ScopeId).Distinct(StringComparer.Ordinal).Count() != document.Scopes.Length)
            throw new AdOperationDeniedException("ad_policy_invalid");
        foreach (var scope in document.Scopes) ValidateScope(scope);
        return document.Scopes;
    }

    public static void ValidateScope(AdScope? scope)
    {
        if (scope is null || !Guid.TryParseExact(scope.ScopeId, "D", out var scopeGuid) || scopeGuid == Guid.Empty ||
            scope.DomainGuid == Guid.Empty || scope.OuGuid == Guid.Empty ||
            string.IsNullOrWhiteSpace(scope.DomainDnsName) || scope.DomainDnsName.Length > 253 ||
            Uri.CheckHostName(scope.DomainDnsName) != UriHostNameType.Dns || scope.DomainDnsName.EndsWith('.') ||
            IPAddress.TryParse(scope.DomainDnsName, out _) ||
            string.IsNullOrWhiteSpace(scope.ControllerFqdn) || scope.ControllerFqdn.Length > 253 ||
            !scope.ControllerFqdn.Contains('.') || scope.ControllerFqdn.EndsWith('.') ||
            Uri.CheckHostName(scope.ControllerFqdn) != UriHostNameType.Dns || IPAddress.TryParse(scope.ControllerFqdn, out _) ||
            !scope.ExactOuDelegationAcknowledged || !scope.NoBroadDirectoryPrivilegesAcknowledged ||
            string.IsNullOrWhiteSpace(scope.MachineAccountSid))
            throw new AdOperationDeniedException("ad_delegation_policy_required");
        try
        {
            var sid = new SecurityIdentifier(scope.MachineAccountSid);
            if (sid.AccountDomainSid is null || sid.Value != scope.MachineAccountSid)
                throw new AdOperationDeniedException("ad_machine_identity_invalid");
        }
        catch (ArgumentException) { throw new AdOperationDeniedException("ad_machine_identity_invalid"); }
    }
}
