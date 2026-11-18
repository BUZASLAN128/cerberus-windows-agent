using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal static partial class UpdaterLab
{
    internal static bool IsLabBuild => false;
    internal static string CurrentVersion => AgentProductVersion.Get(typeof(Program).Assembly);
    internal static int WatchMinutes => 30;

    internal static AgentUpdateBuildMetadata WatchMetadata(AgentUpdateBuildMetadata metadata) => metadata;

    internal static bool IsAdmittedWatchArtifact(string kind, string version, string sha256) => false;

    internal static string? AdmitWatchRollback(string rollbackAttemptId, string targetVersion, string msiSha256) => null;

    internal static AgentUpdateTrust BuildTrust()
        => AgentUpdateTrustBuilder.Build(AgentUpdateBuildMetadata.Read(typeof(Program).Assembly), CurrentVersion, null);

    internal static void RequireLaunch(AgentUpdateJournal active, AgentLifecycleSnapshot lifecycle) { }

    internal static void InterruptUpdaterOnce(AgentUpdateJournal active, AgentUpdatePlan plan,
        AgentLifecycleSnapshot lifecycle, int processId, DateTimeOffset startedUtc, Action<string> log)
    {
        if (active.InstallRequest?.LocalPolicyId is not null)
            throw new InvalidOperationException("Development updater fault authority is missing.");
    }

    internal static void AdmitLaunch(AgentUpdatePlan plan, AgentUpdateInstallRequest request, string transaction)
        => throw new InvalidOperationException("Development launch scope is missing.");
}
