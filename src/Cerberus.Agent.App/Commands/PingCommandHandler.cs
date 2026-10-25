using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Commands;

/// <summary><c>ping</c> (contract v1 (d)): payload <c>{}</c>, result DONE with <c>agent.ping.v1</c>.</summary>
internal sealed class PingCommandHandler : ICommandHandler
{
    public const string Schema = "agent.ping.v1";

    private readonly AgentBuildMetadata _metadata;
    private readonly TimeProvider _time;

    public PingCommandHandler(AgentBuildMetadata metadata, TimeProvider? time = null)
    {
        _metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _time = time ?? TimeProvider.System;
    }

    public string Type => EnvelopeTypes.Ping;

    public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var post = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["schema"] = Schema,
            ["agent_version"] = _metadata.AgentVersion,
            ["build_id"] = _metadata.BuildId,
            ["agent_time"] = _time.GetUtcNow().ToUnixTimeSeconds(),
            ["uptime_seconds"] = Environment.TickCount64 / 1000,
        };
        return Task.FromResult(new CommandResult("DONE", 0, null, null, post));
    }
}
