using System.Threading.Channels;

namespace Cerberus.Agent.Core;

/// <summary>A one-slot, best-effort hint; command authority remains with the next HTTPS heartbeat.</summary>
public sealed class AgentWakeupSignal
{
    private readonly Channel<bool> _pending = Channel.CreateBounded<bool>(new BoundedChannelOptions(1)
    {
        FullMode = BoundedChannelFullMode.DropWrite,
        SingleReader = true,
        SingleWriter = false,
    });

    public void Signal() => _pending.Writer.TryWrite(true);

    public void Clear()
    {
        while (_pending.Reader.TryRead(out _)) { }
    }

    /// <returns>True for a hint; false for the ordinary polling deadline.</returns>
    public async Task<bool> WaitAsync(TimeSpan timeout, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (_pending.Reader.TryRead(out _))
            return true;
        if (timeout <= TimeSpan.Zero)
            return false;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try
        {
            await _pending.Reader.ReadAsync(deadline.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return false;
        }
    }
}
