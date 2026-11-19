using System.Text.Json;

namespace Cerberus.Agent.Core;

/// <summary>Decisions around the install-time health rollback: when the installer must see backend contact and when a failed release is not staged again.</summary>
public static class AgentUpdateRollbackPolicy
{
    /// <summary>Only an automatic attempt that starts from a fully active agent has to prove backend contact before the install commits.</summary>
    public static bool RequiresBackendContact(bool automatic, AgentLifecycleState state)
        => automatic && state == AgentLifecycleState.Active;

    /// <summary>A health-failure record belongs to this attempt when it was written after msiexec started and names the version being installed.</summary>
    public static bool IsCurrentAttemptRecord(DateTimeOffset recordedAtUtc, DateTimeOffset? installerStartedUtc, string? recordExpectedVersion, string planVersion)
        => installerStartedUtc is not null && recordedAtUtc >= installerStartedUtc.Value
            && string.Equals(recordExpectedVersion, planVersion, StringComparison.Ordinal);

    /// <summary>The diagnostic stores the phase as snake_case text; an unknown value yields null.</summary>
    public static AgentInstallerHealthPhase? ParsePhase(string? phase)
        => Enum.GetValues<AgentInstallerHealthPhase>().Cast<AgentInstallerHealthPhase?>()
            .FirstOrDefault(value => string.Equals(JsonNamingPolicy.SnakeCaseLower.ConvertName(value!.Value.ToString()), phase, StringComparison.Ordinal));

    /// <summary>Only an installer health rollback pins the failed sequence. A backend outage, an unknown phase and the pipe and no-answer phases do not,
    /// because a local user can hold or squat the control pipe to cause them; such a rollback is retried at the next check.</summary>
    public static long NextFailedInstallSequence(long previous, string? errorCode, long planSequence, AgentInstallerHealthPhase? rollbackPhase)
        => rollbackPhase is not null && !IsPipeInducible(rollbackPhase.Value) && errorCode == AgentUpdateErrorCodes.MsiFailed
            ? Math.Max(previous, planSequence) : previous;

    private static bool IsPipeInducible(AgentInstallerHealthPhase phase) => phase is
        AgentInstallerHealthPhase.BackendContact or AgentInstallerHealthPhase.PipeConnect or AgentInstallerHealthPhase.PipeAuthority
        or AgentInstallerHealthPhase.StatusRequest or AgentInstallerHealthPhase.StatusResponse or AgentInstallerHealthPhase.StabilityNoAnswer;

    /// <summary>A pending reboot excuses a failed probe only when the old service binary is still in place because its files were locked:
    /// the failure is in the service executable or assembly hash check (both run before the probe, so a later phase means the new files
    /// are on disk and a pending entry is stale or foreign), no timeout or cancellation, and a queued rename whose destination is the file
    /// that phase checked (the .exe for the executable hash, the .dll for the assembly hash); the file as a rename source never excuses.</summary>
    public static bool PendingRebootExcuses(AgentInstallerHealthPhase phase, bool cancelledOrTimedOut, IEnumerable<string> pendingEntries, string runtime)
    {
        if (cancelledOrTimedOut) return false;
        var file = phase switch
        {
            AgentInstallerHealthPhase.ServiceExecutableHash => "Cerberus.Agent.Service.exe",
            AgentInstallerHealthPhase.ServiceAssemblyHash => "Cerberus.Agent.Service.dll",
            _ => null,
        };
        if (file is null) return false;
        var expected = Path.Combine(runtime, file);
        var entries = pendingEntries.ToArray();
        // Entries are (source, destination) pairs; a deletion has an empty destination.
        for (var i = 1; i < entries.Length; i += 2)
        {
            var path = entries[i] ?? string.Empty;
            if (path.StartsWith('!')) path = path[1..];
            if (path.StartsWith(@"\??\", StringComparison.Ordinal)) path = path[4..];
            if (path.Length > 0 && string.Equals(path, expected, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>Automatic staging skips the failed sequence; manual staging is never blocked.</summary>
    public static long? SkipSequenceFor(bool automatic, long failedInstallSequence)
        => automatic && failedInstallSequence > 0 ? failedInstallSequence : null;

    public static bool SkipsSequence(long? skipAtOrBelow, bool isV2, long sequence)
        => skipAtOrBelow is > 0 && isV2 && sequence <= skipAtOrBelow;
}
