using System.Diagnostics;

namespace Cerberus.Agent.Core;

internal sealed class AgentUpdateBitsProgressWatch
{
    internal const uint NoProgressTimeoutSeconds = 900;
    private static readonly TimeSpan NoProgressTimeout = TimeSpan.FromSeconds(NoProgressTimeoutSeconds);
    private static readonly TimeSpan OverallTimeout = TimeSpan.FromHours(1);

    private readonly Func<TimeSpan> _readElapsed;
    private TimeSpan _lastGrowth;
    private ulong _mostBytesTransferred;

    internal AgentUpdateBitsProgressWatch()
    {
        var stopwatch = Stopwatch.StartNew();
        _readElapsed = () => stopwatch.Elapsed;
    }

    internal AgentUpdateBitsProgressWatch(Func<TimeSpan> readElapsed) => _readElapsed = readElapsed;

    internal void ThrowIfOverallTimedOut() => ThrowIfOverallTimedOut(_readElapsed());

    internal void Observe(ulong bytesTransferred)
    {
        var elapsed = _readElapsed();
        ThrowIfOverallTimedOut(elapsed);

        if (bytesTransferred > _mostBytesTransferred)
        {
            _mostBytesTransferred = bytesTransferred;
            _lastGrowth = elapsed;
        }

        if (elapsed - _lastGrowth >= NoProgressTimeout)
            throw new InvalidOperationException("BITS update download failed: no progress.");
    }

    private static void ThrowIfOverallTimedOut(TimeSpan elapsed)
    {
        if (elapsed >= OverallTimeout)
            throw new InvalidOperationException("BITS update download timed out.");
    }
}
