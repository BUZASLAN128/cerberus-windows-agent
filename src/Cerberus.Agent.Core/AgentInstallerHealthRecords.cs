namespace Cerberus.Agent.Core;

public static class AgentInstallerHealthRecords
{
    /// <summary>The failed phase of the newest health-failure record the installer helper wrote for this attempt; null when there is none or its phase is unknown.</summary>
    public static AgentInstallerHealthPhase? NewestPhaseSince(
        string privilegedRoot, DateTimeOffset? installerStartedUtc, string planVersion, Action<string>? log)
    {
        AgentInstallerHealthDiagnostic? newest = null;
        try
        {
            var root = privilegedRoot;
            AgentUpdateSecurity.EnsureProtectedRoot(root);
            foreach (var path in Directory.EnumerateFiles(root, "*.health-failure.json"))
            {
                try
                {
                    var record = AgentUpdateDurableFile.Read<AgentInstallerHealthDiagnostic>(path, root);
                    if (record is not null && AgentUpdateRollbackPolicy.IsCurrentAttemptRecord(record.RecordedAtUtc, installerStartedUtc, record.ExpectedVersion, planVersion)
                        && (newest is null || record.RecordedAtUtc > newest.RecordedAtUtc))
                        newest = record;
                }
                catch (Exception ex)
                {
                    log?.Invoke($"Health failure record skipped: {ex.GetType().Name}.");
                }
            }
        }
        catch (Exception ex)
        {
            log?.Invoke($"Health failure records unreadable: {ex.GetType().Name}.");
        }
        return AgentUpdateRollbackPolicy.ParsePhase(newest?.Phase);
    }
}
