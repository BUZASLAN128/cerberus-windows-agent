namespace Cerberus.Agent.Core;

/// <summary>Decisions around the install-time health rollback: when the installer must see backend contact and when a failed release is not staged again.</summary>
public static class AgentUpdateRollbackPolicy
{
    /// <summary>Only an automatic attempt that starts from a fully active agent has to prove backend contact before the install commits.</summary>
    public static bool RequiresBackendContact(bool automatic, AgentLifecycleState state)
        => automatic && state == AgentLifecycleState.Active;

    /// <summary>A health-failure record belongs to this attempt when it was written after msiexec started.</summary>
    public static bool IsCurrentAttemptRecord(DateTimeOffset recordedAtUtc, DateTimeOffset? installerStartedUtc)
        => installerStartedUtc is not null && recordedAtUtc >= installerStartedUtc.Value;

    /// <summary>Only an installer health rollback pins the failed sequence; other msi_failed cases keep the previous value.</summary>
    public static long NextFailedInstallSequence(long previous, string? errorCode, long planSequence, bool healthRollbackRecorded)
        => healthRollbackRecorded && errorCode == AgentUpdateErrorCodes.MsiFailed ? Math.Max(previous, planSequence) : previous;

    /// <summary>Automatic staging skips the failed sequence; manual staging is never blocked.</summary>
    public static long? SkipSequenceFor(bool automatic, long failedInstallSequence)
        => automatic && failedInstallSequence > 0 ? failedInstallSequence : null;

    public static bool SkipsSequence(long? skipAtOrBelow, bool isV2, long sequence)
        => skipAtOrBelow is > 0 && isV2 && sequence <= skipAtOrBelow;
}
