namespace Cerberus.Agent.Core;

/// <summary>
/// Handles the commands delivered with one heartbeat response. The heartbeat loop
/// awaits only <see cref="ProcessAsync"/>; any longer-running work stays behind this seam.
/// </summary>
public interface IHeartbeatCommandProcessor
{
    Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct);

    /// <summary>
    /// Wakes the result outbox without accepting or running any command. The loop calls it
    /// when the server's control state skips commands. Default: nothing to drain.
    /// </summary>
    void SignalOutbox()
    {
    }
}

/// <summary>Inline ack, dispatch and result for every entry, as the loop always did.</summary>
public sealed class LegacyHeartbeatCommandProcessor : IHeartbeatCommandProcessor
{
    private readonly AgentApiClient _api;
    private readonly CommandDispatcher _dispatcher;
    private readonly TimeSpan _commandTimeout;
    private readonly int _commandConcurrency;

    public LegacyHeartbeatCommandProcessor(
        AgentApiClient api,
        CommandDispatcher dispatcher,
        TimeSpan commandTimeout,
        int commandConcurrency)
    {
        _api = api;
        _dispatcher = dispatcher;
        _commandTimeout = commandTimeout;
        _commandConcurrency = commandConcurrency;
    }

    public async Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct)
    {
        if (commands.Count == 0)
            return;

        using var gate = new SemaphoreSlim(_commandConcurrency, _commandConcurrency);
        var tasks = commands.Select(cmd => DispatchOneCommandAsync(cmd, gate, ct)).ToArray();
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task DispatchOneCommandAsync(AgentCommand cmd, SemaphoreSlim gate, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var timeout = string.Equals(cmd.Type, "agent.update.request", StringComparison.Ordinal)
                ? Max(_commandTimeout, TimeSpan.FromMinutes(20))
                : _commandTimeout;
            await _api.SubmitCommandAckAsync(cmd, ct).ConfigureAwait(false);
            var res = await _dispatcher.DispatchAsync(cmd, timeout, ct).ConfigureAwait(false);
            await _api.SubmitCommandResultAsync(cmd, res, ct).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static TimeSpan Max(TimeSpan left, TimeSpan right)
        => left >= right ? left : right;
}
