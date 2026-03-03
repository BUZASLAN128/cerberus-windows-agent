namespace Cerberus.Agent.Core;

public sealed class CommandDispatcher
{
    private readonly IReadOnlyDictionary<string, ICommandHandler> _handlers;
    private readonly IdempotencyCache _idempotency;
    private readonly string[] _handlerTypes;

    public CommandDispatcher(IEnumerable<ICommandHandler> handlers, IdempotencyCache idempotency)
    {
        var handlerList = handlers.ToList();
        _handlers = handlerList.ToDictionary(h => h.Type, StringComparer.Ordinal);
        _handlerTypes = handlerList.Select(h => h.Type).OrderBy(x => x, StringComparer.Ordinal).ToArray();
        _idempotency = idempotency;
    }

    public IReadOnlyList<string> HandlerTypes => _handlerTypes;

    public async Task<CommandResult> DispatchAsync(AgentCommand cmd, CancellationToken ct)
    {
        if (_idempotency.TryGet(cmd.IdempotencyKey, out var cached))
            return cached;

        if (!_handlers.TryGetValue(cmd.Type, out var handler))
        {
            var unknown = new CommandResult(
                Status: "FAILED",
                ExitCode: null,
                Stdout: null,
                Stderr: $"Unknown command type: {cmd.Type}",
                PostVerify: null);
            _idempotency.Set(cmd.IdempotencyKey, unknown);
            return unknown;
        }

        var res = await handler.HandleAsync(cmd, ct);
        _idempotency.Set(cmd.IdempotencyKey, res);
        return res;
    }
}
