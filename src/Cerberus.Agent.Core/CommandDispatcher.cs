namespace Cerberus.Agent.Core;

/// <summary>
/// Allows a command-specific gate to re-authorize a cached result without
/// re-running the fresh-mutation checks that must not block a legitimate
/// replay. Implementations must keep their authoritative manifest/lifecycle
/// checks around the cached result; authoritative AD handlers deliberately do
/// not use this seam.
/// </summary>
public interface IReplayAwareCommandExecutionGate
{
    Task<CommandResult> ExecuteAuthorizedAsync(
        AgentCommand command,
        CommandResult? cachedResult,
        Func<Task<CommandResult>> execute,
        CancellationToken ct);
}

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
        => await DispatchAsync(cmd, timeout: null, ct).ConfigureAwait(false);

    public async Task<CommandResult> DispatchAsync(AgentCommand cmd, TimeSpan? timeout, CancellationToken ct)
    {
        if (_handlers.TryGetValue(cmd.Type, out var authoritativeHandler) && authoritativeHandler is IAuthoritativeCommandExecutionGate authoritative)
            return await authoritative.ExecuteAuthorizedAsync(cmd,
                (verified, cancel) => DispatchCoreAsync(verified, timeout, cancel, authorized: true, protectedReplay: true), ct).ConfigureAwait(false);
        if (_handlers.TryGetValue(cmd.Type, out var replayHandler) && replayHandler is IReplayAwareCommandExecutionGate replayAware)
        {
            var cached = _idempotency.TryGet(cmd.IdempotencyKey, out var cachedResult) ? cachedResult : null;
            return await replayAware.ExecuteAuthorizedAsync(cmd, cached,
                () => DispatchCoreAsync(cmd, timeout, ct, authorized: true), ct).ConfigureAwait(false);
        }
        if (_handlers.TryGetValue(cmd.Type, out var handler) && handler is ICommandExecutionGate gate)
            return await gate.ExecuteAuthorizedAsync(cmd, () => DispatchCoreAsync(cmd, timeout, ct, authorized: true), ct).ConfigureAwait(false);
        return await DispatchCoreAsync(cmd, timeout, ct).ConfigureAwait(false);
    }

    private async Task<CommandResult> DispatchCoreAsync(AgentCommand cmd, TimeSpan? timeout, CancellationToken ct,
        bool authorized = false, bool protectedReplay = false)
    {
        if (!protectedReplay && _idempotency.TryGet(cmd.IdempotencyKey, out var cached))
            return cached;

        if (!_handlers.TryGetValue(cmd.Type, out var handler))
        {
            var unknown = new CommandResult(
                Status: "FAILED",
                ExitCode: null,
                Stdout: null,
                Stderr: $"Unknown command type: {cmd.Type}",
                PostVerify: null);
            if (!protectedReplay) _idempotency.Set(cmd.IdempotencyKey, unknown);
            return unknown;
        }

        CommandResult res;
        try
        {
            if (timeout is null)
            {
                res = await ExecuteHandlerAsync(ct).ConfigureAwait(false);
            }
            else
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(timeout.Value);
                res = await ExecuteHandlerAsync(timeoutCts.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && timeout is not null)
        {
            res = new CommandResult(
                Status: "FAILED",
                ExitCode: null,
                Stdout: null,
                Stderr: $"Command timed out after {Math.Ceiling(timeout.Value.TotalSeconds)} seconds.",
                PostVerify: new { code = "command_timeout" });
        }
        catch (Exception ex)
        {
            res = new CommandResult(
                Status: "FAILED",
                ExitCode: null,
                Stdout: null,
                Stderr: $"Command handler failed: {ex.GetType().Name}: {ex.Message}",
                PostVerify: new { code = "command_handler_exception" });
        }

        if (!protectedReplay) _idempotency.Set(cmd.IdempotencyKey, res);
        return res;

        Task<CommandResult> ExecuteHandlerAsync(CancellationToken cancel)
            => authorized && handler is IAuthoritativeCommandExecutionGate authoritative
                ? authoritative.HandleAuthorizedAsync(cmd, cancel)
                : authorized && handler is ICommandExecutionGate gated
                ? gated.HandleAuthorizedAsync(cmd, cancel) : handler.HandleAsync(cmd, cancel);
    }
}
