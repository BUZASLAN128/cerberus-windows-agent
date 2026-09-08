using System.Diagnostics;
using System.IO;
using System.Net.Http;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>The installed service owns update decisions. UI/CLI requests contain operations and attempt IDs only.</summary>
internal static class AgentUpdateLocalService
{
    private sealed class IntentionalUpdateCancellationException(string message, CancellationToken cancellationToken)
        : OperationCanceledException(message, cancellationToken);

    private static readonly SemaphoreSlim OperationGate = new(1, 1);
    private static readonly object CancellationGate = new();
    private static CancellationTokenSource? _networkOperation;
    private static string Root => AgentUpdateStager.DefaultStagingRoot;
    private static AgentUpdateJournalStore Journal => new(Root);
    private static AgentUpdateStateStore Projection => AgentUpdateStateStore.CreateDefault();

    /// <summary>
    /// Rewinds only the pre-install state created by the canceled check/stage operation.
    /// Installer evidence and any state that may have crossed the launch fence remain durable.
    /// </summary>
    internal static AgentUpdateJournal TransitionIntentionalCancellation(
        AgentUpdateJournal current,
        AgentUpdateJournal operationStart,
        DateTimeOffset retryAtUtc)
    {
        if (current.Phase == "launch_requested")
            return current with { Phase = AgentUpdateStates.RecoveryRequired };

        if (current.MayHaveStartedInstallation ||
            current.Phase is AgentUpdateStates.Installed or AgentUpdateStates.Blocked or AgentUpdateStates.Quarantined)
            return current;

        var samePriorAttempt = operationStart.AttemptId is not null &&
            string.Equals(current.AttemptId, operationStart.AttemptId, StringComparison.Ordinal);
        if (current.Phase == AgentUpdateStates.Failed && samePriorAttempt)
            return current with { NextCheckUtc = retryAtUtc }; // This is the prior terminal failure, not a synthetic staging failure.

        if (current.Phase == AgentUpdateStates.Current)
            return current with { NextCheckUtc = retryAtUtc };

        if (current.Phase == AgentUpdateStates.Staged)
            return current with { Phase = AgentUpdateStates.Blocked, NextCheckUtc = retryAtUtc };

        if (current.Phase is AgentUpdateStates.AwaitingConsent or AgentUpdateStates.Available)
            return current with { NextCheckUtc = retryAtUtc };

        if (operationStart.Phase is AgentUpdateStates.Failed or AgentUpdateStates.Installed or
            AgentUpdateStates.Blocked or AgentUpdateStates.Quarantined)
        {
            // The current checking/downloading/failed record belongs to this operation. Keep the
            // earlier terminal evidence, but make the next check immediately eligible.
            return current with
            {
                Phase = operationStart.Phase,
                AttemptId = operationStart.AttemptId,
                Automatic = operationStart.Automatic,
                Required = operationStart.Required,
                LifecycleGeneration = operationStart.LifecycleGeneration,
                InstallerResult = operationStart.InstallerResult,
                RetryCount = operationStart.RetryCount,
                NextRetryUtc = operationStart.NextRetryUtc,
                ApplyNotBeforeUtc = operationStart.ApplyNotBeforeUtc,
                RunnerProcessId = operationStart.RunnerProcessId,
                RunnerStartedUtc = operationStart.RunnerStartedUtc,
                InstallerProcessId = operationStart.InstallerProcessId,
                InstallerStartedUtc = operationStart.InstallerStartedUtc,
                InstallationBootId = operationStart.InstallationBootId,
                NextCheckUtc = retryAtUtc,
            };
        }

        return current with
        {
            Phase = AgentUpdateStates.NotChecked,
            AttemptId = null,
            InstallerResult = null,
            RetryCount = 0,
            NextRetryUtc = null,
            ApplyNotBeforeUtc = null,
            RunnerProcessId = null,
            RunnerStartedUtc = null,
            InstallerProcessId = null,
            InstallerStartedUtc = null,
            InstallationBootId = null,
            NextCheckUtc = retryAtUtc,
        };
    }

    internal static bool IsIntentionalCancellation(
        OperationCanceledException error,
        CancellationToken callerToken,
        CancellationToken operationToken,
        bool authorizationChanged)
        => error is IntentionalUpdateCancellationException || authorizationChanged ||
            callerToken.IsCancellationRequested || operationToken.IsCancellationRequested;

    internal static AgentUpdateJournal TransitionFailure(AgentUpdateJournal before)
        => before.Phase == "launch_requested" ? before with { Phase = AgentUpdateStates.RecoveryRequired } :
            before.MayHaveStartedInstallation || before.Phase is
            AgentUpdateStates.Installed or AgentUpdateStates.Failed or AgentUpdateStates.Blocked or AgentUpdateStates.Quarantined
            ? before : before with { Phase = AgentUpdateStates.Failed };

    private static CancellationToken CancellationTokenFor(
        CancellationToken callerToken,
        CancellationToken operationToken)
        => callerToken.IsCancellationRequested ? callerToken : operationToken;

    private static async Task PersistIntentionalCancellationAsync(AgentUpdateJournal operationStart)
    {
        Journal.Change(current => TransitionIntentionalCancellation(current, operationStart, DateTimeOffset.UtcNow));
        await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
    }

    public static async Task<AgentLocalControlResponse> HandleAsync(AgentLocalControlRequest request, CancellationToken ct)
    {
        RequireService();
        if (request.SchemaVersion != AgentLocalControlProtocol.SchemaVersion || request.Operation is not ("status" or "check" or "apply"))
            return new(false, "operation_denied");
        try
        {
            if (request.Operation == "status")
                return await StatusAsync("ok", ct).ConfigureAwait(false);
            if (request.Operation == "check")
            {
                if (!await OperationGate.WaitAsync(0, ct).ConfigureAwait(false))
                    return await StatusAsync("update_busy", ct).ConfigureAwait(false);
                var handedOff = false;
                try
                {
                    var current = Journal.Read();
                    if (current.HasUnfinishedAttempt)
                        return await StatusAsync("update_busy", ct).ConfigureAwait(false);
                    _ = RunManualCheckAsync();
                    handedOff = true;
                    return await StatusAsync("check_started", ct).ConfigureAwait(false);
                }
                finally { if (!handedOff) OperationGate.Release(); }
            }
            if (!AgentUpdateSecurity.IsSafeAttemptId(request.AttemptId))
                return new(false, "attempt_required");
            await OperationGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await ApplyAsync(request.AttemptId!, automatic: false, ct).ConfigureAwait(false);
                return await StatusAsync("apply_admitted", ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                await ReportFailureAsync(ex).ConfigureAwait(false);
                throw;
            }
            finally { OperationGate.Release(); }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(false, AgentUpdateErrorCodes.Classify(ex));
        }
    }

    private static async Task RunManualCheckAsync()
    {
        try { await CheckAndStageOwnedAsync(automatic: false, required: false, CancellationToken.None).ConfigureAwait(false); }
        catch (IntentionalUpdateCancellationException) { }
        catch (Exception ex) { await ReportFailureAsync(ex).ConfigureAwait(false); }
        finally { OperationGate.Release(); }
    }

    public static async Task<AgentUpdatePlan?> CheckAndStageAsync(
        bool automatic,
        bool required,
        CancellationToken ct,
        bool bypassSchedule = false)
    {
        RequireService();
        await OperationGate.WaitAsync(ct).ConfigureAwait(false);
        try { return await CheckAndStageOwnedAsync(automatic, required, ct, bypassSchedule).ConfigureAwait(false); }
        finally { OperationGate.Release(); }
    }

    public static async Task<AgentUpdateCheckResult> CheckOnlyAsync(
        bool automatic,
        CancellationToken ct,
        bool bypassSchedule = false)
    {
        RequireService();
        await OperationGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
            if (automatic && !AllowsAutomatic(lifecycle)) return AgentUpdateCheckResult.None;
            var active = Journal.Read();
            if (active.HasUnfinishedAttempt)
            {
                var existing = ReadPlan(active);
                return existing is null ? AgentUpdateCheckResult.None : new(true, existing.Required, !existing.Required,
                    existing.Version, existing.Channel, existing.Reason, null, existing.ArtifactKind);
            }
            if (automatic && !bypassSchedule && active.NextCheckUtc > DateTimeOffset.UtcNow) return AgentUpdateCheckResult.None;
            var operationStart = active;
            var schedulePersisted = false;
            var authorizationChanged = false;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
            lock (CancellationGate) { _networkOperation = cancellation; }
            try
            {
                Journal.Change(before => before with
                {
                    AttemptId = null, InstallerResult = null, Phase = AgentUpdateStates.Checking,
                    Automatic = automatic, LifecycleGeneration = lifecycle.Generation,
                    NextCheckUtc = DateTimeOffset.UtcNow.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
                });
                schedulePersisted = true;
                await ProjectAsync(cancellation.Token).ConfigureAwait(false);
                using var http = new HttpClient(new HttpClientHandler { MaxAutomaticRedirections = 5 }) { Timeout = TimeSpan.FromSeconds(30) };
                var trust = AgentUpdateTrustFactory.BuildTrust();
                var signal = new AgentUpdateSignal(false, true, trust.ConfiguredManifestUrl, "service_update_check", trust.ExpectedChannel);
                var result = await new AgentUpdateStager(http, trust, Root).CheckAsync(signal, cancellation.Token).ConfigureAwait(false);
                var latestLifecycle = await LoadLifecycleAsync(cancellation.Token).ConfigureAwait(false);
                if (automatic && (latestLifecycle.Generation != lifecycle.Generation || !AllowsAutomatic(latestLifecycle)))
                {
                    authorizationChanged = true;
                    cancellation.Cancel();
                    throw new IntentionalUpdateCancellationException("Update authorization changed.", cancellation.Token);
                }
                Journal.Change(before => before with { AttemptId = null, InstallerResult = null, Phase = result.Available ? AgentUpdateStates.Available : AgentUpdateStates.Current });
                var previous = await Projection.ReadAsync(WindowsDeviceInfo.GetAgentVersion(), cancellation.Token).ConfigureAwait(false);
                await Projection.WriteAsync(previous.Transition(result.Available ? AgentUpdateStates.Available : AgentUpdateStates.Current,
                    WindowsDeviceInfo.GetAgentVersion(), targetVersion: result.Version, channel: result.Channel, markChecked: true)
                    with { AttemptId = null, ReleaseId = null, Sequence = 0 }, cancellation.Token).ConfigureAwait(false);
                return result;
            }
            catch (OperationCanceledException ex) when (schedulePersisted &&
                IsIntentionalCancellation(ex, ct, cancellation.Token, authorizationChanged))
            {
                await PersistIntentionalCancellationAsync(operationStart).ConfigureAwait(false);
                throw new IntentionalUpdateCancellationException(ex.Message,
                    CancellationTokenFor(ct, cancellation.Token));
            }
            catch (OperationCanceledException ex)
            {
                await ReportFailureAsync(ex).ConfigureAwait(false);
                throw;
            }
            catch (Exception ex)
            {
                await ReportFailureAsync(ex).ConfigureAwait(false);
                throw;
            }
            finally { lock (CancellationGate) { if (ReferenceEquals(_networkOperation, cancellation)) _networkOperation = null; } }
        }
        finally { OperationGate.Release(); }
    }

    private static async Task<AgentUpdatePlan?> CheckAndStageOwnedAsync(
        bool automatic,
        bool required,
        CancellationToken ct,
        bool bypassSchedule = false)
    {
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (automatic && !AllowsAutomatic(lifecycle))
            return null;
        var active = Journal.Read();
        if (active.HasUnfinishedAttempt)
        {
            if (required && !active.Required && active.Phase == AgentUpdateStates.AwaitingConsent)
                Journal.Change(before => before with
                {
                    Required = true,
                    ApplyNotBeforeUtc = DateTimeOffset.UtcNow.Add(AgentUpdateJournalStore.Offset(
                        before.ScheduleSeed + ":rollout:" + before.AttemptId, TimeSpan.FromHours(24))),
                });
            return ReadPlan(active);
        }
        if (automatic && !bypassSchedule && active.NextCheckUtc > DateTimeOffset.UtcNow) return null;
        var operationStart = active;
        var schedulePersisted = false;
        var authorizationChanged = false;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (CancellationGate) { _networkOperation = cancellation; }
        try
        {
            Journal.Change(before => before with
            {
                Phase = AgentUpdateStates.Checking, AttemptId = null, InstallerResult = null,
                Automatic = automatic, LifecycleGeneration = lifecycle.Generation,
                Required = required, RetryCount = 0, NextRetryUtc = null, ApplyNotBeforeUtc = null,
                RunnerProcessId = null, RunnerStartedUtc = null, InstallerProcessId = null, InstallerStartedUtc = null,
                InstallationBootId = null,
                NextCheckUtc = DateTimeOffset.UtcNow.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
            });
            schedulePersisted = true;
            await ProjectAsync(cancellation.Token).ConfigureAwait(false);
            using var http = new HttpClient(new HttpClientHandler { MaxAutomaticRedirections = 5 }) { Timeout = TimeSpan.FromSeconds(30) };
            var trust = AgentUpdateTrustFactory.BuildTrust();
            var signal = new AgentUpdateSignal(required, !required, trust.ConfiguredManifestUrl, "service_update_check", trust.ExpectedChannel);
            var stager = new AgentUpdateStager(http, trust, Root);
            var plan = await stager.StageAsync(signal, cancellation.Token).ConfigureAwait(false);
            var latestLifecycle = await LoadLifecycleAsync(cancellation.Token).ConfigureAwait(false);
            if (latestLifecycle.Generation != lifecycle.Generation || (automatic && !AllowsAutomatic(latestLifecycle)))
            {
                authorizationChanged = true;
                cancellation.Cancel();
                throw new IntentionalUpdateCancellationException("Update authorization changed.", cancellation.Token);
            }
            var now = DateTimeOffset.UtcNow;
            Journal.Change(before => before with
            {
                Phase = plan is null ? AgentUpdateStates.Current : AgentUpdateStates.AwaitingConsent,
                Automatic = automatic,
                LifecycleGeneration = lifecycle.Generation,
                Required = required,
                ApplyNotBeforeUtc = plan is null || !required ? null : now.Add(AgentUpdateJournalStore.Offset(
                    before.ScheduleSeed + ":rollout:" + plan.Channel + ":" + plan.Sequence, TimeSpan.FromHours(24))),
                NextCheckUtc = now.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
            });
            await ProjectAsync(cancellation.Token).ConfigureAwait(false);
            return plan;
        }
        catch (OperationCanceledException ex) when (schedulePersisted &&
            IsIntentionalCancellation(ex, ct, cancellation.Token, authorizationChanged))
        {
            await PersistIntentionalCancellationAsync(operationStart).ConfigureAwait(false);
            throw new IntentionalUpdateCancellationException(ex.Message,
                CancellationTokenFor(ct, cancellation.Token));
        }
        catch (OperationCanceledException ex)
        {
            await ReportFailureAsync(ex).ConfigureAwait(false);
            throw;
        }
        catch (Exception ex)
        {
            await ReportFailureAsync(ex).ConfigureAwait(false);
            throw;
        }
        finally
        {
            lock (CancellationGate)
                if (ReferenceEquals(_networkOperation, cancellation)) _networkOperation = null;
        }
    }

    public static async Task HandleHeartbeatAsync(AgentUpdateSignal signal, CancellationToken ct)
    {
        if (!signal.Required && !signal.Recommended)
            return;
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (!AllowsAutomatic(lifecycle))
            return;
        if (!await OperationGate.WaitAsync(0, ct).ConfigureAwait(false)) return;
        _ = RunHeartbeatWorkAsync(signal.Required, ct);
    }

    private static async Task RunHeartbeatWorkAsync(bool required, CancellationToken ct)
    {
        try { await CheckAndStageOwnedAsync(automatic: true, required, ct).ConfigureAwait(false); }
        catch (IntentionalUpdateCancellationException) { }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) { await ReportFailureAsync(ex).ConfigureAwait(false); }
        finally { OperationGate.Release(); }
    }

    public static async Task QuiesceAsync(CancellationToken ct)
    {
        RequireService();
        lock (CancellationGate) { _networkOperation?.Cancel(); }
        await OperationGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Journal.Change(before => before.HasUnfinishedAttempt && !before.MayHaveStartedInstallation
                ? before with { Phase = AgentUpdateStates.Blocked }
                : before);
            AgentUpdateBitsDownloader.Quiesce(Root);
            await ProjectAsync(ct).ConfigureAwait(false);
        }
        finally { OperationGate.Release(); }
    }

    public static async Task ReconcileOnServiceStartAsync(CancellationToken ct)
    {
        RequireService();
        AgentUpdateSecurity.EnsureProtectedRoot(Root);
        await OperationGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            AgentUpdateBitsDownloader.Quiesce(Root);
            await ReconcileOwnedAsync(ct, allowHealth: false).ConfigureAwait(false);
            Journal.Change(before => before.NextCheckUtc is not null ? before : before with
            {
                NextCheckUtc = DateTimeOffset.UtcNow.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
            });
            await ProjectAsync(ct).ConfigureAwait(false);
        }
        finally { OperationGate.Release(); }
    }

    public static async Task RunScheduledAsync(CancellationToken ct)
    {
        RequireService();
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            if (!await OperationGate.WaitAsync(0, ct).ConfigureAwait(false)) continue;
            try
            {
                await ReconcileOwnedAsync(ct).ConfigureAwait(false);
                var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
                if (!AllowsAutomatic(lifecycle)) continue;
                var active = Journal.Read();
                var now = DateTimeOffset.UtcNow;
                if (active.AttemptId is not null &&
                    ((active.Required && active.Phase == AgentUpdateStates.AwaitingConsent && active.ApplyNotBeforeUtc <= now) ||
                     (active.Phase == AgentUpdateStates.RetryableBusy && active.NextRetryUtc <= now)))
                    await ApplyAsync(active.AttemptId, automatic: true, ct).ConfigureAwait(false);
                else if (!active.HasUnfinishedAttempt && active.NextCheckUtc <= now)
                    await CheckAndStageOwnedAsync(automatic: true, required: false, ct).ConfigureAwait(false);
            }
            catch (IntentionalUpdateCancellationException) when (!ct.IsCancellationRequested) { }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { await ReportFailureAsync(ex).ConfigureAwait(false); }
            finally { OperationGate.Release(); }
        }
    }

    private static async Task ApplyAsync(string attemptId, bool automatic, CancellationToken ct)
    {
        var active = Journal.Read();
        if (active.AttemptId != attemptId)
            throw new InvalidOperationException("Update attempt does not match the requested consent.");
        if (active.MayHaveStartedInstallation || active.Phase == "launch_requested")
            return; // Idempotent apply never launches a second runner.
        if (active.Phase is not (AgentUpdateStates.Staged or AgentUpdateStates.AwaitingConsent or AgentUpdateStates.RetryableBusy))
            throw new InvalidOperationException("Update attempt cannot be applied.");
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (automatic && (!AllowsAutomatic(lifecycle) || active.LifecycleGeneration != lifecycle.Generation))
            throw new InvalidOperationException("Automatic update authorization changed.");
        if (active.RetryCount >= 3 || (active.NextRetryUtc is not null && active.NextRetryUtc > DateTimeOffset.UtcNow))
            throw new InvalidOperationException("Update installer retry is not admitted.");
        var plan = ReadPlan(active) ?? throw new InvalidOperationException("Update plan is missing.");
        var attemptDirectory = AgentUpdateSecurity.ResolveAttemptDirectory(Root, attemptId);
        var runtimeDirectory = Path.GetDirectoryName(AgentUpdateCoordinator.ResolveUpdaterPath())!;
        var runner = AgentUpdateRunnerFiles.Prepare(runtimeDirectory, attemptDirectory);
        using (await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false))
        {
            lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
            if (automatic && (!AllowsAutomatic(lifecycle) || active.LifecycleGeneration != lifecycle.Generation))
                throw new InvalidOperationException("Automatic update authorization changed.");
            AgentUpdateRunnerFiles.ValidateForLaunch(runtimeDirectory, attemptDirectory);
            Journal.ChangeAttempt(attemptId, before => before with
            {
                Phase = "launch_requested", LifecycleGeneration = lifecycle.Generation, Automatic = automatic,
                InstallerResult = null, NextRetryUtc = null,
            });
            var start = new ProcessStartInfo(runner) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(runner)! };
            start.ArgumentList.Add("--attempt");
            start.ArgumentList.Add(attemptId);
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Update runner launch failed.");
            Journal.ChangeAttempt(attemptId, before => before with
            {
                RunnerProcessId = process.Id, RunnerStartedUtc = new DateTimeOffset(process.StartTime.ToUniversalTime()),
            });
        }
        await ProjectAsync(ct).ConfigureAwait(false);
    }

    private static async Task ReconcileOwnedAsync(CancellationToken ct, bool allowHealth = true)
    {
        var active = Journal.Read();
        if (active.AttemptId is null) return;
        if (active.Phase is "launch_requested" or "install_may_have_started" or AgentUpdateStates.Installing)
        {
            if (!IsProcessAlive(active.RunnerProcessId, active.RunnerStartedUtc))
                Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.RecoveryRequired });
        }
        else if (active.Phase == AgentUpdateStates.RetryableBusy && active.NextRetryUtc is null)
        {
            Journal.ChangeAttempt(active.AttemptId, before => before with
            {
                RetryCount = Math.Min(3, before.RetryCount + 1),
                NextRetryUtc = DateTimeOffset.UtcNow.AddSeconds(Math.Min(30, 4 * Math.Pow(2, before.RetryCount))),
                Phase = before.RetryCount >= 2 ? AgentUpdateStates.Failed : AgentUpdateStates.RetryableBusy,
            });
        }
        else if (active.Phase is AgentUpdateStates.HealthPending or AgentUpdateStates.PendingReboot)
        {
            if (!allowHealth) return; // Startup must open the pipe before health can prove local readiness.
            var plan = ReadPlan(active) ?? throw new InvalidOperationException("Installed update plan is missing.");
            if (active.Phase == AgentUpdateStates.PendingReboot && active.InstallationBootId == AgentUpdateBootIdentity.Read())
            {
                await ProjectAsync(ct).ConfigureAwait(false);
                return;
            }
            if (string.Equals(WindowsDeviceInfo.GetAgentVersion(), plan.Version, StringComparison.Ordinal) &&
                IsCanonicalServiceProcess())
            {
                await LoadLifecycleAsync(ct).ConfigureAwait(false);
                AgentLocalControlResponse ready;
                try { ready = await Cerberus.Agent.App.Control.AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("status"), ct).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.RecoveryRequired });
                    await ProjectAsync(ct).ConfigureAwait(false);
                    return;
                }
                if (!ready.Success || ready.CurrentVersion != plan.Version)
                {
                    Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.RecoveryRequired });
                    await ProjectAsync(ct).ConfigureAwait(false);
                    return;
                }
                Journal.ChangeAttempt(active.AttemptId, before => before with
                {
                    Phase = AgentUpdateStates.Installed, HealthyInstalledSequence = plan.Sequence,
                    HealthyInstalledVersion = plan.Version,
                });
            }
            else
                Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.RecoveryRequired });
        }
        else if (active.Phase is AgentUpdateStates.Downloading or AgentUpdateStates.Checking)
            Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.Failed });
        await ProjectAsync(ct).ConfigureAwait(false);
    }

    private static bool IsCanonicalServiceProcess()
    {
        var directory = Path.GetDirectoryName(AgentUpdateCoordinator.ResolveUpdaterPath())!;
        var expected = Path.Combine(directory, "Cerberus.Agent.Service.exe");
        if (!string.Equals(Environment.ProcessPath, expected, StringComparison.OrdinalIgnoreCase)) return false;
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Cerberus\WindowsAgent", writable: false);
        foreach (var (file, name) in new[] { (expected, "serviceExeSha256"), (Path.Combine(directory, "Cerberus.Agent.Service.dll"), "serviceAssemblySha256") })
        {
            var digest = key?.GetValue(name)?.ToString();
            if (digest is null || digest.Length != 64) return false;
            using var stream = File.OpenRead(file);
            if (!Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).Equals(digest, StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }

    private static bool IsProcessAlive(int? id, DateTimeOffset? startedUtc)
    {
        if (id is null || startedUtc is null) return false;
        try
        {
            using var process = Process.GetProcessById(id.Value);
            return !process.HasExited && new DateTimeOffset(process.StartTime.ToUniversalTime()) == startedUtc;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { return false; }
    }

    private static AgentUpdatePlan? ReadPlan(AgentUpdateJournal active)
    {
        if (active.AttemptId is null) return null;
        var directory = AgentUpdateSecurity.ResolveAttemptDirectory(Root, active.AttemptId);
        return AgentUpdateDurableFile.Read<AgentUpdatePlan>(Path.Combine(directory, AgentUpdateSecurity.PlanFileName), directory);
    }

    private static async Task<AgentLocalControlResponse> StatusAsync(string code, CancellationToken ct)
    {
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        var state = await Projection.ReadAsync(WindowsDeviceInfo.GetAgentVersion(), ct).ConfigureAwait(false);
        return new(true, code, lifecycle.State.ToString(), state.State, state.AttemptId,
            WindowsDeviceInfo.GetAgentVersion(), state.TargetVersion, lifecycle.Generation);
    }

    private static async Task ProjectAsync(CancellationToken ct)
    {
        var active = Journal.Read();
        var old = await Projection.ReadAsync(WindowsDeviceInfo.GetAgentVersion(), ct).ConfigureAwait(false);
        var plan = ReadPlan(active);
        var state = active.Phase is "launch_requested" or "install_may_have_started" ? AgentUpdateStates.Installing : active.Phase;
        var next = old.Transition(state, WindowsDeviceInfo.GetAgentVersion(), targetVersion: plan?.Version,
            channel: plan?.Channel, attemptId: active.AttemptId, sequence: plan?.Sequence,
            msiExitCode: active.InstallerResult?.MsiExitCode, retryCount: active.RetryCount,
            requiresReboot: state == AgentUpdateStates.PendingReboot) with
        {
            AttemptId = active.AttemptId,
            TargetVersion = plan?.Version,
            Sequence = plan?.Sequence ?? 0,
            ReleaseId = plan is null ? null : plan.Channel + ":" + plan.Sequence,
            Policy = active.Required ? "required" : "recommended",
            RetryAfterUtc = active.NextRetryUtc?.ToString("O"),
            HealthState = state == AgentUpdateStates.Installed ? "healthy" :
                state is AgentUpdateStates.HealthPending or AgentUpdateStates.PendingReboot ? "pending" :
                state == AgentUpdateStates.RecoveryRequired ? "unhealthy" : "unknown",
            RollbackState = state == AgentUpdateStates.RecoveryRequired ? "unavailable" : "none",
            LastErrorCode = active.InstallerResult?.ErrorCode,
            LastErrorMessage = null,
        };
        if (next with { LastTransitionUtc = old.LastTransitionUtc } != old)
            await Projection.WriteAsync(next, ct).ConfigureAwait(false);
    }

    private static async Task ReportFailureAsync(Exception error)
    {
        try
        {
            Journal.Change(TransitionFailure);
            await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception) { /* A corrupt/unwritable journal stays unavailable; never create replacement success state. */ }
    }

    private static Task<AgentLifecycleSnapshot> LoadLifecycleAsync(CancellationToken ct)
        => new DurableAgentLifecycleStateStore().LoadAsync(ct);
    private static bool AllowsAutomatic(AgentLifecycleSnapshot lifecycle)
        => AgentLifecycleStates.AllowsAutomaticNetwork(lifecycle.State) && lifecycle.QuiescenceComplete;
    private static void RequireService()
    {
        if (!AgentUpdateSecurity.IsLocalSystem())
            throw new UnauthorizedAccessException("Only the installed SYSTEM service owns updates.");
    }
}
