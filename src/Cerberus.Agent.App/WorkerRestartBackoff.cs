namespace Cerberus.Agent.App;

/// <summary>
/// Delay before the service supervisor restarts a worker that ended on its own after a short run (for example a
/// revoke that could not be recorded while the lifecycle file stays unwritable). The delay doubles up to
/// <see cref="MaxDelay"/> and resets after a run of at least <see cref="HealthyRun"/>. A worker stopped on purpose
/// (generation change, dormant state) restarts at once.
/// </summary>
internal sealed class WorkerRestartBackoff
{
    internal static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(2);
    internal static readonly TimeSpan MaxDelay = TimeSpan.FromMinutes(4);
    internal static readonly TimeSpan HealthyRun = TimeSpan.FromSeconds(60);

    private TimeSpan _delay = InitialDelay;
    private DateTimeOffset _notBefore = DateTimeOffset.MinValue;

    public bool CanStart(DateTimeOffset now) => now >= _notBefore;

    /// <summary>Records that a worker ended. <paramref name="planned"/> is true when the supervisor stopped it.</summary>
    public void OnWorkerEnded(DateTimeOffset startedUtc, DateTimeOffset now, bool planned)
    {
        if (planned)
            return;
        if (now - startedUtc >= HealthyRun)
        {
            _delay = InitialDelay;
            return;
        }

        _notBefore = now + _delay;
        _delay = _delay * 2 > MaxDelay ? MaxDelay : _delay * 2;
    }
}
