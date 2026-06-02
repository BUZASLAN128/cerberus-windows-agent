using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public sealed record AgentIdentity(string AgentId, string TenantId);

public sealed record TokenPair(
    [property: JsonPropertyName("agent_refresh_token")] string RefreshToken,
    [property: JsonPropertyName("agent_access_token")] string AccessToken);

public sealed record AgentCommand(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("idempotency_key")] string IdempotencyKey,
    [property: JsonPropertyName("payload")] object Payload);

public sealed record VersionPolicy(
    [property: JsonPropertyName("minimum_supported_version")] string? MinimumSupportedVersion,
    [property: JsonPropertyName("latest_recommended_version")] string? LatestRecommendedVersion,
    [property: JsonPropertyName("blocked_versions")] IReadOnlyList<string>? BlockedVersions,
    [property: JsonPropertyName("decision")] string Decision,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("download_hint")] string? DownloadHint);

public sealed record HeartbeatResponse(
    [property: JsonPropertyName("pending_commands")] IReadOnlyList<AgentCommand> PendingCommands,
    [property: JsonPropertyName("next_poll_seconds")] int NextPollSeconds,
    [property: JsonPropertyName("server_time")] long ServerTime,
    [property: JsonPropertyName("server_time_utc")] string? ServerTimeUtc,
    [property: JsonPropertyName("command_batch_size")] int CommandBatchSize,
    [property: JsonPropertyName("next_snapshot_seconds")] int NextSnapshotSeconds,
    [property: JsonPropertyName("config_version")] string? ConfigVersion,
    [property: JsonPropertyName("lifecycle_state")] string? LifecycleState,
    [property: JsonPropertyName("registration_state")] string? RegistrationState,
    [property: JsonPropertyName("claim_required")] bool ClaimRequired,
    [property: JsonPropertyName("manifest_version")] string? ManifestVersion,
    [property: JsonPropertyName("managed_account_manifest_hash")] string? ManagedAccountManifestHash,
    [property: JsonPropertyName("manifest_fresh_until")] string? ManifestFreshUntil,
    [property: JsonPropertyName("require_manifest_before_unlock")] bool RequireManifestBeforeUnlock,
    [property: JsonPropertyName("agent_status")] string? AgentStatus,
    [property: JsonPropertyName("version_policy")] VersionPolicy? VersionPolicy,
    [property: JsonPropertyName("update")] IReadOnlyDictionary<string, JsonElement>? Update,
    [property: JsonPropertyName("revoke")] IReadOnlyDictionary<string, JsonElement>? Revoke,
    [property: JsonPropertyName("quarantine")] IReadOnlyDictionary<string, JsonElement>? Quarantine,
    [property: JsonPropertyName("tenant_name")] string? TenantName = null);

public sealed record AgentSelfDeactivateRequest(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("reason_code")] string ReasonCode,
    [property: JsonPropertyName("reason")] string? Reason);

public sealed record AgentSelfDeactivateResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("agent_id")] string AgentId,
    [property: JsonPropertyName("registration_state")] string RegistrationState,
    [property: JsonPropertyName("revoked_tokens")] int RevokedTokens);
