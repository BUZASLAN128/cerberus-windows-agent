namespace Cerberus.Agent.Core;

/// <summary>Process-local time of the last accepted heartbeat. Never persisted; a restarted service starts without contact.</summary>
public static class AgentBackendContact
{
    private static long _lastUtcTicks;

    public static DateTimeOffset? LastSuccessUtc
        => Interlocked.Read(ref _lastUtcTicks) is var ticks and > 0 ? new DateTimeOffset(ticks, TimeSpan.Zero) : null;

    public static void MarkSuccess() => Interlocked.Exchange(ref _lastUtcTicks, DateTime.UtcNow.Ticks);
}
