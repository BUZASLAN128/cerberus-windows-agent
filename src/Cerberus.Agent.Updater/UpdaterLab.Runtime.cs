using Cerberus.Agent.App;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal static partial class UpdaterLab
{
    internal static bool IsLabBuild => AgentUpdateDefaults.LabPolicyB64.Length > 0;
    internal static string CurrentVersion => WindowsDeviceInfo.GetAgentVersion();

    internal static int WatchMinutes
    {
        get
        {
            var lab = AgentUpdateLabRuntime.Resolve() ?? throw new InvalidOperationException("Development watch scope is missing.");
            var minutes = lab.Policy.WatchMinutesOverride ?? 30;
            return minutes >= 5 ? minutes : throw new InvalidOperationException("Development watch duration is invalid.");
        }
    }

    internal static AgentUpdateBuildMetadata WatchMetadata(AgentUpdateBuildMetadata metadata) => metadata with
    {
        ManifestPublicKeysB64 = AgentUpdateDefaults.ManifestPublicKeysB64,
        ReleaseChannel = AgentUpdateDefaults.ReleaseChannel,
        AllowedSignerKeyIdentity = AgentUpdateDefaults.AllowedSignerKeyIdentity,
        AllowUnsignedDevBuild = AgentUpdateDefaults.AllowUnsignedDevBuild,
    };

    internal static bool IsAdmittedWatchArtifact(string kind, string version, string sha256)
        => AgentUpdateLabRuntime.IsAdmittedLabArtifact(kind, version, sha256);

    internal static string AdmitWatchRollback(string rollbackAttemptId, string targetVersion, string msiSha256)
    {
        var lab = AgentUpdateLabRuntime.Resolve() ?? throw new InvalidOperationException("Development rollback scope is missing.");
        var transaction = Guid.NewGuid().ToString("D");
        AgentUpdateLabRuntimeAdmission.AdmitRollback(lab.Policy, lab.Context, rollbackAttemptId, targetVersion, msiSha256, transaction);
        return transaction;
    }

    internal static AgentUpdateTrust BuildTrust() => AgentUpdateTrustFactory.BuildTrust();

    internal static void RequireLaunch(AgentUpdateJournal active, AgentLifecycleSnapshot lifecycle)
        => AgentUpdateLabRuntime.RequireLaunch(active, lifecycle);

    internal static void InterruptUpdaterOnce(AgentUpdateJournal active, AgentUpdatePlan plan,
        AgentLifecycleSnapshot lifecycle, int processId, DateTimeOffset startedUtc, Action<string> log)
        => AgentUpdateLabFaults.InterruptUpdaterOnce(active, plan, lifecycle, processId, startedUtc, log);

    internal static void AdmitLaunch(AgentUpdatePlan plan, AgentUpdateInstallRequest request, string transaction)
    {
        var lab = AgentUpdateLabRuntime.Resolve() ?? throw new InvalidOperationException("Development launch scope is missing.");
        AgentUpdateLabRuntimeAdmission.AdmitLaunch(lab.Policy, lab.Context, plan, request, transaction);
    }
}
