using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Telemetry;

/// <summary>Reads the Defender and SMB1 posture facts. Implementations throw on failure; the cache decides what to report.</summary>
internal interface ISecurityPostureReader
{
    object ReadDefender(CancellationToken ct);

    object ReadSmb1(CancellationToken ct);
}

/// <summary>
/// Background cache for the WMI-backed posture keys (<c>defender_av</c>, <c>smb1</c>). The section collector only reads
/// <see cref="Current"/>; the WMI call never runs on the snapshot path. Each key has its own single-flight slot: while a
/// query is still running (the scripting COM call ignores cancellation) no second query starts, so a hung provider
/// holds one thread per key instead of one per snapshot. The first read kicks the first refresh.
/// </summary>
internal sealed class SecurityPostureCache : IDisposable
{
    internal static readonly TimeSpan RefreshAfter = TimeSpan.FromMinutes(15);
    internal static readonly TimeSpan RetryAfterFailure = TimeSpan.FromMinutes(5);
    internal static readonly TimeSpan Ttl = TimeSpan.FromHours(2);

    public static SecurityPostureCache Shared { get; } = new(new WmiSecurityPostureReader(), TimeProvider.System);

    private readonly TimeProvider _time;
    private readonly CancellationTokenSource _cts = new();
    private readonly Slot _defender;
    private readonly Slot _smb1;

    public SecurityPostureCache(ISecurityPostureReader reader, TimeProvider time)
    {
        _time = time;
        _defender = new Slot("defender_av", reader.ReadDefender);
        _smb1 = new Slot("smb1", reader.ReadSmb1);
    }

    /// <summary>The last completed result per key, or <c>{ status: "unavailable" }</c> while none exists or it is older than the TTL.</summary>
    public IReadOnlyDictionary<string, object?> Current()
    {
        var result = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            [_defender.Key] = _defender.Get(_time, _cts.Token),
            [_smb1.Key] = _smb1.Get(_time, _cts.Token),
        };
        return result;
    }

    /// <summary>Starts the first refresh without waiting for it; single-flight like <see cref="Current"/>.</summary>
    public void Warm() => _ = Current();

    public void Dispose() => _cts.Cancel();

    private sealed class Slot(string key, Func<CancellationToken, object> read)
    {
        private readonly object _gate = new();
        private object? _value;
        private DateTimeOffset _checkedAt;
        private DateTimeOffset _nextAttempt = DateTimeOffset.MinValue;
        private Task? _inFlight;

        public string Key { get; } = key;

        public object Get(TimeProvider time, CancellationToken ct)
        {
            lock (_gate)
            {
                var now = time.GetUtcNow();
                if (_inFlight is not { IsCompleted: false } && now >= _nextAttempt && !ct.IsCancellationRequested)
                    _inFlight = Task.Run(() => Refresh(time, ct), CancellationToken.None);
                return _value is not null && now - _checkedAt <= Ttl ? _value : SecurityPostureProbe.Unavailable;
            }
        }

        private void Refresh(TimeProvider time, CancellationToken ct)
        {
            object? value = null;
            try
            {
                value = read(ct);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                TelemetrySectionCapture.Log?.Warn(
                    $"Telemetry section security {Key} {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)} at={ExceptionSite.FirstFrame(ex)}");
            }

            lock (_gate)
            {
                var now = time.GetUtcNow();
                if (value is not null)
                {
                    _value = value;
                    _checkedAt = now;
                }

                _nextAttempt = now + (value is not null ? RefreshAfter : RetryAfterFailure);
            }
        }
    }
}
