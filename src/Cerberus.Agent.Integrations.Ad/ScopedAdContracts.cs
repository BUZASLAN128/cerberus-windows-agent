using Cerberus.Agent.Core;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Integrations.Ad;

// These are internal service inputs, never a deserialization target for remote commands.
public sealed record AdAccountBinding(string TenantId, string AgentId, string ManagedAccountId,
    string AssignmentId, string ScopeId, string Username);
public sealed record AdCommandTarget(AdAccountBinding Binding, Guid DomainGuid, Guid OuGuid, string DomainDnsName);
public sealed record AdCredentialRequest(string CredentialRequestId, DateTimeOffset ExpiresAt, RdpCredentialMetadata Metadata);
public sealed record AdPreparedCredential(AdCredentialRequest Request, RdpCredentialEnvelope Envelope);
public sealed record AdScope(
    [property: JsonPropertyName("scope_id")] string ScopeId,
    [property: JsonPropertyName("controller_fqdn")] string ControllerFqdn,
    [property: JsonPropertyName("domain_guid")] Guid DomainGuid,
    [property: JsonPropertyName("ou_guid")] Guid OuGuid,
    [property: JsonPropertyName("domain_dns_name")] string? DomainDnsName = null,
    [property: JsonPropertyName("machine_account_sid")] string? MachineAccountSid = null,
    [property: JsonPropertyName("exact_ou_delegation_acknowledged")] bool ExactOuDelegationAcknowledged = false,
    [property: JsonPropertyName("no_broad_directory_privileges_acknowledged")] bool NoBroadDirectoryPrivilegesAcknowledged = false);
public sealed record AdUserIdentity(Guid ObjectGuid, string Sid);
public sealed record AdUserState(AdUserIdentity Identity, Guid ParentGuid, string Username,
    bool Disabled, bool Protected, bool LeafUser);
public sealed record AdOwnership(AdAccountBinding Binding, AdScope Scope, AdUserIdentity Identity,
    bool PasswordInitialized, bool Deleted, bool DisableRequested = false, AdPreparedCredential? PreparedCredential = null);
public sealed record AdOperationResult(bool Success, string Code, AdUserIdentity? Identity = null, AdPreparedCredential? PreparedCredential = null);

public interface IScopedAdUserProvider
{
    Task<AdOperationResult> PrepareAsync(AdCommandTarget target, AdCredentialRequest request, CancellationToken ct);
    Task<AdOperationResult> ActivateAsync(AdCommandTarget target, AdUserIdentity expectedIdentity, string credentialProfileId, CancellationToken ct);
    Task<AdOperationResult> DisableAsync(AdCommandTarget target, AdUserIdentity expectedIdentity, string reason, CancellationToken ct);
    Task<AdOperationResult> DeleteAsync(AdCommandTarget target, AdUserIdentity expectedIdentity, bool confirmed, string reason, CancellationToken ct);
    Task<AdOperationResult> CreateAsync(AdAccountBinding binding, string initialPassword, bool activate, CancellationToken ct);
    Task<AdOperationResult> DisableAsync(AdAccountBinding binding, string reason, CancellationToken ct);
    Task<AdOperationResult> DeleteAsync(AdAccountBinding binding, bool confirmed, string reason, CancellationToken ct);
}

/// <summary>Directory I/O boundary. Mutations must recheck scope and the owned object; a timed-out mutation has an uncertain outcome.</summary>
public interface IAdDirectorySession : IDisposable
{
    void VerifyScope();
    AdUserState? FindUsername(string username);
    AdUserState? Read(Guid objectGuid);
    AdUserState CreateDisabled(string username);
    void InitializePassword(AdUserIdentity identity, string username, string password);
    void SetDisabled(AdUserIdentity identity, string username, bool disabled);
    void DeleteLeaf(AdUserIdentity identity, string username);
}

public interface IAdDirectoryBoundary
{
    // Must verify SYSTEM identity, member-workstation/server role, joined domain and pinned controller/domain/OU.
    IAdDirectorySession Open(AdScope scope, CancellationToken ct = default);
}

public interface IAdOwnershipStore
{
    IDisposable AcquireLease(AdAccountBinding binding);
    AdOwnership? Read(AdAccountBinding binding);
    void Write(AdOwnership ownership);
}

public sealed class AdOperationDeniedException(string code) : Exception(code)
{
    public string Code { get; } = code;
}
