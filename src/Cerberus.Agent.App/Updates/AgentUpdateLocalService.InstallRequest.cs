using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

/// <summary>
/// Signed operator request to install the newest release. The scheduler preserves existing policy while staging;
/// only a verified stage promotes the request to an immediately due install, without blocking the command queue.
/// </summary>
internal static partial class AgentUpdateLocalService
{
    /// <summary>Latest start a request may ask for, and how long it stays valid after that start.</summary>
    internal static readonly TimeSpan MaxInstallRequestDelay = TimeSpan.FromHours(24);
    internal static readonly TimeSpan InstallRequestRetryDelay = TimeSpan.FromMinutes(5);
    internal const int MaxInstallRequestAttempts = 3;

    private static volatile Func<bool>? _serverQuarantined;
    private static IAgentLogger _requestLog = NullAgentLogger.Instance;

    internal enum InstallRequestStep { None, Drop, Run }

    /// <summary>Server build: the worker's signed state, so a quarantine pauses the update scheduler.</summary>
    internal static void ConnectSignedState(Func<bool> quarantined, IAgentLogger log)
    {
        _requestLog = log;
        _serverQuarantined = quarantined;
    }

    /// <summary>The server build counts as quarantined until the worker connects its signed state, or when it cannot be read.</summary>
    private static bool Quarantined()
        => Quarantined(_serverQuarantined, AgentBuildProfile.IsServer);

    internal static bool Quarantined(Func<bool>? signedState, bool isServer)
    {
        if (!isServer)
            return false;
        try { return signedState?.Invoke() ?? true; }
        catch (Exception) { return true; }
    }

    /// <summary>Records the request for the scheduler; false when the agent state does not allow automatic updates.</summary>
    public static async Task<bool> RequestInstallAsync(DateTimeOffset notBeforeUtc, string commandId, string campaignId,
        string idempotencyKey, AgentUpdateExpectedPlan? expectedPlan, CancellationToken ct)
    {
        RequireService();
        return await RequestInstallAsync(notBeforeUtc, LoadLifecycleAsync, Journal.Change, Quarantined, ct,
            commandId, campaignId, idempotencyKey, expectedPlan).ConfigureAwait(false);
    }

    internal static async Task<bool> RequestInstallAsync(DateTimeOffset notBeforeUtc,
        Func<CancellationToken, Task<AgentLifecycleSnapshot>> loadLifecycle,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        Func<bool> quarantined, CancellationToken ct, string? commandId = null, string? campaignId = null,
        string? idempotencyKey = null, AgentUpdateExpectedPlan? expectedPlan = null)
    {
        var lifecycle = await loadLifecycle(ct).ConfigureAwait(false);
        if (!AllowsAutomatic(lifecycle) || quarantined())
            return false;
        var request = new AgentUpdateInstallRequest(notBeforeUtc, lifecycle.Generation, notBeforeUtc + MaxInstallRequestDelay,
            CommandId: commandId, CampaignId: campaignId, IdempotencyKey: idempotencyKey, ExpectedPlan: expectedPlan);
        if (!request.IsValid()) return false;
        var accepted = false;
        change(before =>
        {
            before = ExpireInstallRequestAuthority(before, DateTimeOffset.UtcNow);
            if (request.IsCorrelated && before.InstallRequest is { } existing)
            {
                if (existing.SameIdentity(request)) { accepted = true; return before; }
                if (existing.CommandId == commandId || existing.TerminalReason is null) return before;
            }
            accepted = true;
            return before with { InstallRequest = request };
        });
        return accepted;
    }

    /// <summary>
    /// A request lapses on another lifecycle generation, when automatic updates are not allowed, or at its expiry; a due
    /// one waits only for a running install to finish.
    /// </summary>
    internal static InstallRequestStep NextInstallRequestStep(
        AgentUpdateJournal active, long lifecycleGeneration, bool allowed, DateTimeOffset now)
        => active.InstallRequest is not { IsPending: true } request ? InstallRequestStep.None
            : request.LifecycleGeneration != lifecycleGeneration || !allowed || request.ExpiresUtc <= now
                ? InstallRequestStep.Drop
            : active.MayHaveStartedInstallation || active.Phase == "launch_requested" || request.NotBeforeUtc > now
                ? InstallRequestStep.None
                : InstallRequestStep.Run;

    /// <summary>The request after a failed staging: due again after the retry delay, or null once tries or time run out.</summary>
    internal static AgentUpdateInstallRequest? RetryInstallRequest(AgentUpdateInstallRequest request, DateTimeOffset now)
    {
        var next = request with { Attempts = request.Attempts + 1, NotBeforeUtc = now + InstallRequestRetryDelay };
        return next.Attempts >= MaxInstallRequestAttempts || next.NotBeforeUtc >= request.ExpiresUtc ? null : next;
    }

    /// <summary>After successful staging, promotes this generation's consent-waiting attempt to an immediately due install.</summary>
    internal static AgentUpdateJournal TransitionInstallRequested(AgentUpdateJournal before, long lifecycleGeneration, DateTimeOffset now)
        => before.AttemptId is not null && before.Phase == AgentUpdateStates.AwaitingConsent &&
           before.LifecycleGeneration == lifecycleGeneration && (!before.Required || before.ApplyNotBeforeUtc is null || before.ApplyNotBeforeUtc > now)
            ? before with { Required = true, ApplyNotBeforeUtc = now,
                RequiredInstallAttemptId = before.RequiredPolicyGeneration is null ? before.AttemptId : null,
                InstallRequestAuthorityExpiresUtc = before.RequiredPolicyGeneration is null ? before.InstallRequest?.ExpiresUtc : null }
            : before;

    /// <summary>
    /// First scheduler step. True when the tick ends here: quarantined (everything waits, a pending request included),
    /// automatic updates not allowed, or the request was staged.
    /// </summary>
    private static async Task<bool> HoldOrRunInstallRequestAsync(
        AgentUpdateJournal active, AgentLifecycleSnapshot lifecycle, CancellationToken ct)
        => await HoldOrRunInstallRequestAsync(active, lifecycle, Quarantined, Journal.Change,
            async required => (await CheckAndStageOwnedAsync(automatic: true, required, ct,
                bypassSchedule: true, installRequest: active.InstallRequest).ConfigureAwait(false)) is not null,
            _requestLog, ct).ConfigureAwait(false);

    internal static async Task<bool> HoldOrRunInstallRequestAsync(AgentUpdateJournal active,
        AgentLifecycleSnapshot lifecycle, Func<bool> quarantined,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        Func<bool, Task<bool>> stage, IAgentLogger log, CancellationToken ct)
    {
        var allowed = AllowsAutomatic(lifecycle);
        if (NextInstallRequestStep(active, lifecycle.Generation, allowed, DateTimeOffset.UtcNow) == InstallRequestStep.Drop)
        {
            await RunInstallRequestAsync(active, lifecycle.Generation, allowed, change, stage, log, ct).ConfigureAwait(false);
            return quarantined() || !allowed;
        }
        if (quarantined())
            return true;
        var staged = await RunInstallRequestAsync(active, lifecycle.Generation, allowed, change, stage, log, ct).ConfigureAwait(false);
        return staged || !allowed;
    }

    /// <summary>
    /// Drops a lapsed request or stages a due one without inventing required-policy provenance on a failed check.
    /// The request is cleared once staging returns; a failed staging keeps it for a later try and rethrows, so the failure
    /// is reported like any other. True when this tick handled a staging check, even when no update was available.
    /// </summary>
    internal static async Task<bool> RunInstallRequestAsync(
        AgentUpdateJournal active,
        long lifecycleGeneration,
        bool allowed,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        Func<bool, Task<bool>> stage,
        IAgentLogger log,
        CancellationToken ct)
    {
        var step = NextInstallRequestStep(active, lifecycleGeneration, allowed, DateTimeOffset.UtcNow);
        if (step == InstallRequestStep.None)
            return false;
        var request = active.InstallRequest!;
        if (step == InstallRequestStep.Drop)
        {
            change(before => Replace(before, request, Finish(request, request.LifecycleGeneration != lifecycleGeneration
                ? "lifecycle_changed" : !allowed ? "automatic_updates_disabled" : "expired")));
            log.Info($"Install request {request.CommandId ?? "legacy"} dropped: " + (request.LifecycleGeneration != lifecycleGeneration ? "lifecycle changed."
                : !allowed ? "automatic updates are not allowed." : "expired."));
            return false;
        }

        bool staged;
        try
        {
            // Existing independent required policy is carried by the staging owner.
            // The request's install authority is granted only after staging succeeds.
            staged = await stage(false).ConfigureAwait(false);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            var terminal = ex is AgentUpdatePlanMismatchException ? "plan_mismatch"
                : ex is InstallReleaseUnavailableException ? "release_unavailable" : null;
            var retry = terminal is null ? RetryInstallRequest(request, DateTimeOffset.UtcNow) : null;
            retry ??= Finish(request with { Attempts = Math.Min(MaxInstallRequestAttempts, request.Attempts + 1) }, terminal ?? "staging_failed");
            change(before => Replace(before, request, retry));
            log.Warn(retry is null || retry.TerminalReason is not null
                ? $"Install request {request.CommandId ?? "legacy"} staging failed; no tries left."
                : $"Install request {request.CommandId ?? "legacy"} staging failed; next try at {retry.NotBeforeUtc:O}.");
            throw;
        }

        var after = change(before => !MatchesPending(before.InstallRequest, request) ? before
            : request.IsCorrelated && (before.InstallRequest!.VerifiedRelease is not { } verified ||
                request.ExpectedPlan is { } expected && !expected.Matches(verified) ||
                staged && (before.AttemptId is null || before.LifecycleGeneration != lifecycleGeneration))
                ? before with { InstallRequest = AnchorTerminal(before, Finish(before.InstallRequest!, "release_unavailable")) }
            : staged ? TransitionInstallRequested(before with { InstallRequest = request.IsCorrelated
                    ? before.InstallRequest! with { BoundAttemptId = before.AttemptId }
                    : null }, lifecycleGeneration, DateTimeOffset.UtcNow)
                : before with { InstallRequest = AnchorTerminal(before, Finish(before.InstallRequest!, "current")) });
        log.Info($"Install request {request.CommandId ?? "legacy"} handled: update state {after.Phase}.");
        return true;
    }

    /// <summary>An automatic install about to launch waits while the agent is quarantined.</summary>
    internal static void HoldWhileQuarantined(bool automatic, CancellationToken ct, Func<bool>? quarantined = null)
    {
        if (automatic && (quarantined ?? Quarantined)())
            throw new IntentionalUpdateCancellationException("Update held while quarantined.", ct);
    }

    internal static void HoldExpiredInstallRequest(AgentUpdateJournal active, bool automatic, CancellationToken ct)
    {
        if (!automatic || active.MayHaveStartedInstallation || active.Phase == "launch_requested") return;
        active = ExpireInstallRequestAuthority(active, DateTimeOffset.UtcNow);
        var policy = active.Required && active.RequiredPolicyGeneration == active.LifecycleGeneration;
        var request = active.Required && active.RequiredInstallAttemptId == active.AttemptId &&
            active.InstallRequestAuthorityExpiresUtc > DateTimeOffset.UtcNow;
        // Existing manual installer-busy retries have neither request authority nor its expiry marker.
        var manualRetry = active.Phase == AgentUpdateStates.RetryableBusy && !active.Required &&
            active.RequiredInstallAttemptId is null && active.InstallRequestAuthorityExpiresUtc is null;
        if (!policy && !request && !manualRetry)
            throw new IntentionalUpdateCancellationException("Automatic install authority is unavailable or expired.", ct);
    }

    internal static AgentUpdateJournal ExpireInstallRequestAuthority(AgentUpdateJournal active, DateTimeOffset now)
    {
        if (active.MayHaveStartedInstallation || active.Phase is "launch_requested" or AgentUpdateStates.Installed or
            AgentUpdateStates.Failed or AgentUpdateStates.Quarantined ||
            active.Phase == AgentUpdateStates.Blocked && active.ReconciliationSnapshot is null ||
            active.RequiredInstallAttemptId is null && active.InstallRequestAuthorityExpiresUtc is null)
            return active;
        var receipt = active.InstallRequest;
        var matching = active.RequiredInstallAttemptId is { } sourceAttempt && receipt is not null &&
            receipt.BoundAttemptId == sourceAttempt && sourceAttempt == active.AttemptId && receipt.LifecycleGeneration == active.LifecycleGeneration;
        var deadline = active.InstallRequestAuthorityExpiresUtc ?? (matching ? receipt!.ExpiresUtc : DateTimeOffset.MinValue);
        if (matching && receipt!.ExpiresUtc < deadline) deadline = receipt.ExpiresUtc;
        var tracked = active with { InstallRequestAuthorityExpiresUtc = deadline };
        return deadline > now && active.RequiredInstallAttemptId == active.AttemptId && receipt?.TerminalReason != "expired"
            ? tracked : tracked with { RequiredInstallAttemptId = null,
                Required = active.Required && active.RequiredPolicyGeneration is not null };
    }

    private static AgentUpdateJournal ReadInstallAuthority(AgentUpdateJournalStore journal)
    {
        var active = journal.Read();
        return ExpireInstallRequestAuthority(active, DateTimeOffset.UtcNow) == active ? active
            : journal.Change(before => ExpireInstallRequestAuthority(before, DateTimeOffset.UtcNow));
    }

    internal static AgentUpdateJournal TransitionLaunchRequested(AgentUpdateJournal before, long generation, bool automatic, CancellationToken ct)
    {
        before = ExpireInstallRequestAuthority(before, DateTimeOffset.UtcNow);
        HoldExpiredInstallRequest(before, automatic, ct);
        // Explicit local consent is its own source; an old signed request must not obstruct its later busy retries.
        return before with { Phase = "launch_requested", LifecycleGeneration = generation, Automatic = automatic,
            InstallerResult = null, NextRetryUtc = null,
            Required = before.Required && (automatic || before.RequiredPolicyGeneration is not null),
            RequiredInstallAttemptId = automatic ? before.RequiredInstallAttemptId : null,
            InstallRequestAuthorityExpiresUtc = automatic ? before.InstallRequestAuthorityExpiresUtc : null };
    }

    private static AgentUpdateJournal Replace(
        AgentUpdateJournal journal, AgentUpdateInstallRequest expected, AgentUpdateInstallRequest? next)
        => MatchesPending(journal.InstallRequest, expected) ? journal with { InstallRequest = AnchorTerminal(journal, next) } : journal;

    private static bool MatchesPending(AgentUpdateInstallRequest? current, AgentUpdateInstallRequest expected)
        => current is { IsPending: true } && current.SameIdentity(expected) && current.Attempts == expected.Attempts &&
           current.NotBeforeUtc == expected.NotBeforeUtc && current.ExpiresUtc == expected.ExpiresUtc;

    private static AgentUpdateInstallRequest? Finish(AgentUpdateInstallRequest request, string reason)
        => request.IsCorrelated ? request with { TerminalReason = reason, TerminalUtc = DateTimeOffset.UtcNow } : null;

    private sealed class InstallReleaseUnavailableException() : InvalidOperationException("Requested update release is not available for installation.");
}
