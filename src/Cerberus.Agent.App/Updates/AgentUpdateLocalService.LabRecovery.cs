using System.IO;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static partial class AgentUpdateLocalService
{
    /// <summary>Only a compiled lab campaign may retry a runner proven not to have crossed the flushed MSI fence.</summary>
    private static async Task<bool> ReconcileUnstartedLabRunnerAsync(AgentUpdateJournal observed, CancellationToken ct)
    {
        var policy = AgentUpdateLabPolicy.Parse(AgentUpdateDefaults.LabPolicyB64, AgentUpdateDefaults.ReleaseChannel,
            AgentUpdateDefaults.AllowUnsignedDevBuild, AgentBuildProfile.IsServer);
        if (policy is null || observed.InstallRequest?.LocalPolicyId != policy.CampaignId) return false;
        var directory = AgentUpdateSecurity.ResolveAttemptDirectory(Root, observed.AttemptId!);
        var path = Path.Combine(directory, AgentUpdateRunnerFiles.ExecutionLockFileName);
        AgentUpdateSecurity.ValidateProtectedPath(path, directory, allowMissing: true);
        FileStream execution;
        try { execution = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException ex) when (IsRunnerLockContention(ex.HResult)) { return true; }
        // Match updater lock order. The execution lock is nonblocking; never delete/recreate a contested lock.
        using (execution)
        using (await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false))
        {
            Journal.ChangeAttempt(observed.AttemptId!, current => RetryUnstartedLabRunner(current, observed));
        }
        return true;
    }

    internal static bool IsRunnerLockContention(int hresult) => (hresult & 0xffff) is 32 or 33;

    internal static AgentUpdateJournal RetryUnstartedLabRunner(AgentUpdateJournal current, AgentUpdateJournal observed)
        => current == observed && current.Phase == "launch_requested" && current.InstallRequest?.LocalPolicyId is not null
            ? current with { Phase = AgentUpdateStates.RetryableBusy, NextRetryUtc = null,
                RunnerProcessId = null, RunnerStartedUtc = null }
            : current;
}
