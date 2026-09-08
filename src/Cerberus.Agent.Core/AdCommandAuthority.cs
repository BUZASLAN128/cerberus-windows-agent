using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public sealed record AdCommandAuthority(
    [property: JsonPropertyName("tenant_id")] string TenantId,
    [property: JsonPropertyName("agent_id")] string AgentId,
    [property: JsonPropertyName("expires_at")] DateTimeOffset ExpiresAt,
    [property: JsonPropertyName("command")] AgentCommand Command);

/// <summary>Fetches current authority before execution and supplies its canonical command. Replay belongs to protected handler state.</summary>
public interface IAuthoritativeCommandExecutionGate : ICommandHandler
{
    Task<CommandResult> ExecuteAuthorizedAsync(AgentCommand command,
        Func<AgentCommand, CancellationToken, Task<CommandResult>> execute, CancellationToken ct);
    Task<CommandResult> HandleAuthorizedAsync(AgentCommand command, CancellationToken ct);
}
