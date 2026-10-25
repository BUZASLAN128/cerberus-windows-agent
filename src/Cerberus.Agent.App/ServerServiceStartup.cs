#if CERBERUS_SERVER_PROFILE
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App;

/// <summary>
/// Server-profile start-up gates of the service: the data-folder trust check and the pending signed revoke
/// recovery that must finish before the first heartbeat. Delegates keep it testable without a live service.
/// </summary>
internal sealed class ServerServiceStartup
{
    private readonly Func<bool> _revokePending;
    private readonly Func<CancellationToken, Task> _drainOutbox;
    private readonly Func<CancellationToken, Task> _recoverRevoke;
    private readonly Func<bool> _replayAvailable;
    private readonly Func<bool> _networkStopped;
    private readonly Action _stopNetwork;
    private readonly IAgentLogger _log;

    /// <param name="revokePending">Whether a signed revoke is stored for the current agent.</param>
    /// <param name="drainOutbox">One outbox pass that delivers the stored DONE result.</param>
    /// <param name="recoverRevoke">Runs the revoke record when its result is already final.</param>
    /// <param name="replayAvailable">Whether the command replay store is readable.</param>
    /// <param name="networkStopped">True once the automatic network was stopped (by this class or the revoke handler).</param>
    /// <param name="stopNetwork">Stops the automatic network.</param>
    public ServerServiceStartup(Func<bool> revokePending,
        Func<CancellationToken, Task> drainOutbox, Func<CancellationToken, Task> recoverRevoke,
        Func<bool> replayAvailable, Func<bool> networkStopped, Action stopNetwork, IAgentLogger log)
    {
        _revokePending = revokePending ?? throw new ArgumentNullException(nameof(revokePending));
        _drainOutbox = drainOutbox ?? throw new ArgumentNullException(nameof(drainOutbox));
        _recoverRevoke = recoverRevoke ?? throw new ArgumentNullException(nameof(recoverRevoke));
        _replayAvailable = replayAvailable ?? throw new ArgumentNullException(nameof(replayAvailable));
        _networkStopped = networkStopped ?? throw new ArgumentNullException(nameof(networkStopped));
        _stopNetwork = stopNetwork ?? throw new ArgumentNullException(nameof(stopNetwork));
        _log = log ?? throw new ArgumentNullException(nameof(log));
    }

    /// <summary>Before anything writes under the data folder, the logger included.</summary>
    public static void EnsureDataRoot(Func<bool> dataRootTrusted)
    {
        if (dataRootTrusted())
            return;
        Console.Error.WriteLine("Service mode stopped: the server data folder is not trusted.");
        throw new InvalidOperationException("The server data folder is not trusted.");
    }

    /// <summary>
    /// Delivers the DONE result and runs the revoke record before the first heartbeat. Returns false when the
    /// automatic network must stay off; the supervisor then restarts the worker (with a growing delay), which retries.
    /// </summary>
    public async Task<bool> RecoverPendingRevokeAsync(CancellationToken serviceToken, CancellationToken ct)
    {
        var revokePending = _revokePending();
        if (revokePending)
        {
            try
            {
                await _drainOutbox(serviceToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.Error($"Pending signed revoke: the result outbox failed ({ex.GetType().Name}); automatic network stays off.");
                _stopNetwork();
            }
        }
        if (!_networkStopped())
            await _recoverRevoke(ct).ConfigureAwait(false);
        if (revokePending && !_networkStopped() && _revokePending() && !_replayAvailable())
        {
            _log.Error("Pending signed revoke and the command replay store is unreadable; automatic network stays off.");
            _stopNetwork();
        }
        return !_networkStopped();
    }
}
#endif
