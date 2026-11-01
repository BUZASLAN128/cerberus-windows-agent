using System.Diagnostics;
using System.IO;
using System.Net.Http;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>The installed service owns update decisions. UI/CLI requests contain operations and attempt IDs only.</summary>
internal static partial class AgentUpdateLocalService
{

    private static async Task ProjectAsync(CancellationToken ct)
    {
        var active = Journal.Read();
        var old = await Projection.ReadAsync(WindowsDeviceInfo.GetAgentVersion(), ct).ConfigureAwait(false);
        var plan = ReadPlan(active);
        var completed = CompleteInstallRequest(active, plan, DateTimeOffset.UtcNow);
        if (completed.InstallRequest != active.InstallRequest)
        {
            var expected = active.InstallRequest;
            active = Journal.Change(before => before.InstallRequest == expected && before.AttemptId == active.AttemptId
                ? before with { InstallRequest = completed.InstallRequest } : before);
            plan = ReadPlan(active);
        }
        var state = active.Phase is "launch_requested" or "install_may_have_started" ? AgentUpdateStates.Installing : active.Phase;
        var next = old.Transition(state, WindowsDeviceInfo.GetAgentVersion(), targetVersion: plan?.Version,
            channel: plan?.Channel, attemptId: active.AttemptId, sequence: plan?.Sequence,
            msiExitCode: active.InstallerResult?.MsiExitCode, retryCount: active.RetryCount,
            requiresReboot: state == AgentUpdateStates.PendingReboot) with
        {
            AttemptId = active.AttemptId,
            TargetVersion = plan?.Version,
            Sequence = plan?.Sequence ?? 0,
            ReleaseId = plan is null ? null : AgentUpdateExpectedPlan.ReleaseIdentity(plan.Channel, plan.Sequence),
            ArtifactSha256 = plan?.Sha256,
            CampaignId = null,
            CommandId = null,
            Policy = active.Required ? "required" : "recommended",
            RetryAfterUtc = active.NextRetryUtc?.ToString("O"),
            HealthState = state == AgentUpdateStates.Installed ? "healthy" :
                state is AgentUpdateStates.HealthPending or AgentUpdateStates.PendingReboot ? "pending" :
                state == AgentUpdateStates.RecoveryRequired ? "unhealthy" : "unknown",
            RollbackState = state == AgentUpdateStates.RecoveryRequired ? "unavailable" : "none",
            LastErrorCode = active.InstallerResult?.ErrorCode,
            LastErrorMessage = null,
        };
        next = ProjectInstallRequest(active, plan, next);
        if (next with { LastTransitionUtc = old.LastTransitionUtc } != old)
            await Projection.WriteAsync(next, ct).ConfigureAwait(false);
    }

    internal static AgentUpdateJournal CompleteInstallRequest(AgentUpdateJournal active, AgentUpdatePlan? plan, DateTimeOffset now)
    {
        active = ExpireInstallRequestAuthority(active, now);
        if (active.InstallRequest is not { IsCorrelated: true, BoundAttemptId: not null } request ||
            request.TerminalReason is not (null or "expired"))
            return active;
        var bound = active.AttemptId == request.BoundAttemptId && active.LifecycleGeneration == request.LifecycleGeneration &&
            plan is not null && request.VerifiedRelease is { } release &&
            release.Matches(AgentUpdateExpectedPlan.FromPlan(plan));
        // A deferred Blocked state preserves a pre-install attempt; it is not a final outcome.
        var reason = !bound ? null : active.Phase switch
        {
            AgentUpdateStates.Installed => "installed",
            AgentUpdateStates.Failed or AgentUpdateStates.Quarantined => "attempt_failed",
            AgentUpdateStates.Blocked when active.ReconciliationSnapshot is null => "attempt_failed",
            _ => null,
        };
        if (reason is null && !RequestInstallationStarted(active, request) && request.ExpiresUtc <= now)
            reason = "expired";
        return reason is null || reason == request.TerminalReason ? active : active with
        {
            InstallRequest = AnchorTerminal(active, request with { TerminalReason = reason, TerminalUtc = now }),
        };
    }

    internal static AgentUpdateState ProjectInstallRequest(AgentUpdateJournal active, AgentUpdatePlan? plan, AgentUpdateState state)
    {
        if (active.InstallRequest is not { IsCorrelated: true } request)
            return state with { CampaignId = null, CommandId = null, ArtifactSha256 = plan?.Sha256 };
        var bound = request.BoundAttemptId is not null && request.BoundAttemptId == active.AttemptId &&
            active.LifecycleGeneration == request.LifecycleGeneration && plan is not null &&
            request.VerifiedRelease is { } release && release.Matches(AgentUpdateExpectedPlan.FromPlan(plan));
        if (request.TerminalReason is not null &&
            (request.TerminalJournalPhase != active.Phase || request.TerminalJournalAttemptId != active.AttemptId ||
             request.TerminalReason == "expired" && RequestInstallationStarted(active, request) ||
             request.BoundAttemptId is not null && !bound ||
             plan is not null && request.VerifiedRelease is { } completedRelease &&
             !completedRelease.Matches(AgentUpdateExpectedPlan.FromPlan(plan))))
            return state with { CampaignId = null, CommandId = null }; // Keep the old receipt local to its own attempt.
        // A pending request never labels an unrelated attempt or its terminal phase.
        var phase = request.TerminalReason switch
        {
            "current" => AgentUpdateStates.Current,
            "installed" => AgentUpdateStates.Installed,
            not null => AgentUpdateStates.Failed,
            _ => bound ? state.State : AgentUpdateStates.Checking,
        };
        return state with
        {
            State = phase,
            CampaignId = request.CampaignId,
            CommandId = request.CommandId,
            TargetVersion = request.VerifiedRelease?.Version ?? request.ExpectedPlan?.Version,
            ReleaseId = request.VerifiedRelease?.ReleaseId,
            ArtifactSha256 = request.VerifiedRelease?.ArtifactSha256,
            AttemptId = bound ? request.BoundAttemptId : null,
            Sequence = bound ? plan!.Sequence : 0,
            MsiExitCode = bound ? state.MsiExitCode : null,
            RequiresReboot = bound && state.RequiresReboot,
            LastErrorCode = request.TerminalReason is not (null or "current" or "installed")
                ? "install_request_" + request.TerminalReason : bound ? state.LastErrorCode : null,
            LastErrorMessage = null,
            LastTransitionUtc = request.TerminalUtc?.ToString("O") ?? state.LastTransitionUtc,
            HealthState = bound ? state.HealthState : "unknown",
        };
    }

    private static bool RequestInstallationStarted(AgentUpdateJournal journal, AgentUpdateInstallRequest request)
        => journal.AttemptId == request.BoundAttemptId &&
           (journal.MayHaveStartedInstallation || journal.Phase == "launch_requested");

    private static AgentUpdateInstallRequest? AnchorTerminal(AgentUpdateJournal journal, AgentUpdateInstallRequest? request)
        => request?.TerminalReason is not null
            ? request with { TerminalJournalPhase = journal.Phase, TerminalJournalAttemptId = journal.AttemptId }
            : request;
}
