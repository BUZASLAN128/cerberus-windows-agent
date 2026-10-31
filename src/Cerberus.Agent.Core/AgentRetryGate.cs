namespace Cerberus.Agent.Core;

/// <summary>Monotonic retry pacing for durable command replies.</summary>
internal sealed class AgentRetryGate(TimeProvider time)
{
    private readonly object _gate = new();
    private int _failures;
    private long _notBefore;

    public bool CanTry { get { lock (_gate) return time.GetTimestamp() >= _notBefore; } }
    internal long NotBefore { get { lock (_gate) return _notBefore; } }

    public void Succeeded()
    {
        lock (_gate) { _failures = 0; _notBefore = 0; }
    }

    public void Failed(Exception exception)
    {
        lock (_gate)
        {
            var seconds = Math.Min(300, Math.Pow(2, Math.Min(++_failures, 8)) + Random.Shared.NextDouble());
            if (exception is AgentHttpException { RetryAfter: { } retryAfter })
                seconds = Math.Max(seconds, retryAfter.TotalSeconds);
            var candidate = time.GetTimestamp() + (long)(seconds * time.TimestampFrequency);
            _notBefore = Math.Max(_notBefore, candidate);
        }
    }
}
