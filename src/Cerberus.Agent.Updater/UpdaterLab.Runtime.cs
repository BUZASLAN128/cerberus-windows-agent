using Cerberus.Agent.App;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal static partial class UpdaterLab
{
    internal static bool IsLabBuild => AgentUpdateDefaults.LabPolicyB64.Length > 0;
    internal static string CurrentVersion => WindowsDeviceInfo.GetAgentVersion();

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
