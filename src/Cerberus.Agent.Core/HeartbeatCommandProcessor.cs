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
    private readonly IAgentLogger? _managedDelayLog;
    private readonly TimeProvider _time;
    private static readonly TimeSpan ManagedDelayWarning = TimeSpan.FromSeconds(60);

    public LegacyHeartbeatCommandProcessor(
        AgentApiClient api,
        CommandDispatcher dispatcher,
        TimeSpan commandTimeout,
        int commandConcurrency,
        IAgentLogger? managedDelayLog = null,
        TimeProvider? time = null)
    {
        _api = api;
        _dispatcher = dispatcher;
        _commandTimeout = commandTimeout;
        _commandConcurrency = commandConcurrency;
        _managedDelayLog = managedDelayLog;
        _time = time ?? TimeProvider.System;
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
        CancellationTokenSource? watchStop = null;
        if (_managedDelayLog is not null && IsManagedCommand(cmd.Type))
        {
            watchStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _ = WarnOnManagedDelayAsync(watchStop.Token);
        }
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
            watchStop?.Cancel();
            watchStop?.Dispose();
            gate.Release();
        }
    }

    private async Task WarnOnManagedDelayAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(ManagedDelayWarning, _time, ct).ConfigureAwait(false);
            if (!ct.IsCancellationRequested)
                WarnBestEffort("Managed account command has been pending for at least 60 seconds; heartbeat processing may be delayed.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception) { /* Diagnostics are best-effort and never gate command completion. */ }
    }

    private static bool IsManagedCommand(string? type) => type is
        "windows.local_user.create" or "windows.local_user.disable" or "windows.local_user.delete" or
        "windows.ad_user.create" or "windows.ad_user.disable" or "windows.ad_user.delete";

    private void WarnBestEffort(string message)
    {
        try { _managedDelayLog?.Warn(message); }
        catch (Exception) { /* Diagnostics cannot change command authority or completion. */ }
    }

    private static TimeSpan Max(TimeSpan left, TimeSpan right)
        => left >= right ? left : right;
}
