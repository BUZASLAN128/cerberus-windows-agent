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

public sealed record HeartbeatResponse(
    [property: JsonPropertyName("pending_commands")] IReadOnlyList<AgentCommand> PendingCommands,
    [property: JsonPropertyName("next_poll_seconds")] int NextPollSeconds,
    [property: JsonPropertyName("server_time")] long ServerTime,
    [property: JsonPropertyName("command_batch_size")] int CommandBatchSize);

