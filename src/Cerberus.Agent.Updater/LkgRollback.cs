using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

// The host holds host.lock across this path, including installer wait and reconciliation.
internal static class LkgRollback
{
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan RetryLimit = TimeSpan.FromHours(24);
    private const int MaximumAttempts = 3;

    internal static void Run(LkgWatchHostContext context, AgentUpdateWatchRecord watch,
        Func<AgentUpdateLkgStore, string?, AgentUpdateLkgRecord?> readLkg)
    {
        if (!AgentBuildProfile.IsServer || !AgentUpdateSecurity.IsLocalSystem() || context.Journal is not { } expected)
            return;
        if (context.Store.UpdatesRoot != AgentUpdateSecurity.NormalizeRoot(AgentUpdateSecurity.DefaultPrivilegedRoot))
            throw new InvalidOperationException("Rollback requires the canonical update root.");

        var active = context.JournalStore.Read();
        if (!SameAuthority(active, expected, watch.AttemptId) || LkgWatchHostWindows.HasInstallerProcess(active))
            return;

        var native = LkgWatchHostWindows.Observe();
        if (native.Generation is not { } generation || native.Service.InstallerMutexHeld)
            return;

        var rollingBack = active.Phase == AgentUpdateWatchJournal.RollingBack;
        if (rollingBack && watch.Outcome == AgentUpdateWatchOutcomes.RollbackFailed)
        {
            Finish(context, active, watch, AgentUpdateWatchOutcomes.RollbackFailed, AgentUpdateWatchJournal.RollbackFailed, null);
            return;
        }
        if (generation != active.LifecycleGeneration || IsThirdVersion(native.InstalledVersion, watch, rollingBack) ||
            rollingBack && watch.Outcome == AgentUpdateWatchOutcomes.Superseded)
        {
            if (rollingBack)
                Finish(context, active, watch, AgentUpdateWatchOutcomes.Superseded, AgentUpdateWatchJournal.WatchUnavailable, null);
            else
                CloseBeforeRollback(context, watch, AgentUpdateWatchOutcomes.Superseded, AgentUpdateWatchJournal.WatchUnavailable);
            return;
        }

        var lkg = readLkg(context.Store, watch.ReplacedVersion);
        if (lkg is null)
        {
            if (rollingBack)
                Finish(context, active, watch, AgentUpdateWatchOutcomes.RollbackFailed, AgentUpdateWatchJournal.RollbackFailed, null);
            else
                CloseBeforeRollback(context, watch, AgentUpdateWatchOutcomes.ForwardOnlyFailed, AgentUpdateWatchJournal.PostCommitUnhealthy);
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (rollingBack)
        {
            if (active.AlertCode == AgentUpdateErrorCodes.RebootRequired && active.AlertAttemptId == active.RollbackAttemptId &&
                string.Equals(active.InstallationBootId, native.BootId, StringComparison.OrdinalIgnoreCase))
                return;
            // On reboot or host death the installed identity is the durable success receipt.
            if (VerifiedTarget(native, lkg, active.LifecycleGeneration))
            {
                Finish(context, active, watch, AgentUpdateWatchOutcomes.RolledBack, AgentUpdateWatchJournal.PostCommitRollback, lkg);
                return;
            }
            if (Expired(active, now))
            {
                Finish(context, active, watch, AgentUpdateWatchOutcomes.RollbackFailed, AgentUpdateWatchJournal.RollbackFailed, null);
                return;
            }
            if (watch.Outcome == AgentUpdateWatchOutcomes.RolledBack ||
                active.RollbackStartedUtc is { } last && now - last < RetryDelay)
                return;
        }

        if (!context.InstalledManifestVerified || native.Identity is not { } identity ||
            !MatchesWatchedRuntime(native, watch, active.LifecycleGeneration))
            return;

        if (lkg.ProductCode == identity.ProductCode || InstalledTargetProduct(lkg.ProductCode))
        {
            if (rollingBack)
                Finish(context, active, watch, AgentUpdateWatchOutcomes.RollbackFailed, AgentUpdateWatchJournal.RollbackFailed, null);
            else
                CloseBeforeRollback(context, watch, AgentUpdateWatchOutcomes.ForwardOnlyFailed, AgentUpdateWatchJournal.RollbackFailed);
            return;
        }

        Launch(context, active, watch, lkg);
    }

    private static void Launch(LkgWatchHostContext context, AgentUpdateJournal active, AgentUpdateWatchRecord watch,
        AgentUpdateLkgRecord lkg)
    {
        var store = context.Store;
        var rollbackId = Guid.NewGuid().ToString("N");
        var now = DateTimeOffset.UtcNow;
        var arguments = AgentUpdateRollbackCommand.Arguments(AgentUpdateSecurity.DefaultPrivilegedRoot, rollbackId, now);
        var msiLogPath = arguments[^1];
        AgentUpdateSecurity.ValidateProtectedPath(msiLogPath, store.UpdatesRoot, allowMissing: true);
        Directory.CreateDirectory(Path.GetDirectoryName(msiLogPath)!);
        AgentUpdateSecurity.ValidateProtectedPath(Path.GetDirectoryName(msiLogPath)!, store.UpdatesRoot, allowMissing: false);

        AgentUpdateJournal launch;
        Process process;
        DateTimeOffset invocationStartedUtc;
        using (AgentUpdateLaunchFence.AcquireAsync(CancellationToken.None).GetAwaiter().GetResult())
        {
            var current = context.JournalStore.Read();
            var native = LkgWatchHostWindows.Observe();
            if (!SameAuthority(current, active, watch.AttemptId) || LkgWatchHostWindows.HasInstallerProcess(current) ||
                !MatchesWatchedRuntime(native, watch, active.LifecycleGeneration) || InstalledTargetProduct(lkg.ProductCode))
                return;

            AgentUpdateSecurity.ValidateProtectedPath(store.MsiPath, store.UpdatesRoot, allowMissing: false);
            using var msi = File.OpenRead(store.MsiPath);
            if (msi.Length != lkg.MsiLength || !LkgWatchHost.HashMatches(lkg.MsiSha256, Convert.ToHexString(SHA256.HashData(msi))))
                return;

            AgentUpdateJournal Claim(AgentUpdateJournal before) => before with
            {
                Phase = AgentUpdateWatchJournal.RollingBack,
                RollbackAttemptId = rollbackId,
                RollbackFirstUtc = before.RollbackFirstUtc ?? now,
                RollbackStartedUtc = now,
                InstallationBootId = native.BootId,
                InstallerProcessId = null,
                InstallerStartedUtc = null,
                AlertCode = null,
                AlertAttemptId = null,
            };
            launch = Claim(current);
            if (!Patch(context, current, watch, Claim)) return;

            AgentUpdateWatchStore.Write(store.UpdatesRoot, watch with { Outcome = AgentUpdateWatchOutcomes.RollbackPending });
            var transaction = UpdaterLab.AdmitWatchRollback(rollbackId, lkg.Version, lkg.MsiSha256);
            var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "msiexec.exe"))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = store.Root,
            };
            foreach (var argument in arguments)
                start.ArgumentList.Add(argument);
            if (transaction is not null)
                start.ArgumentList.Add(AgentUpdaterContract.LabTransactionProperty + "=" + transaction);

            var claimed = context.JournalStore.Read();
            if (!SameAuthority(claimed, launch, watch.AttemptId)) return;
            if (LkgWatchHostWindows.HasInstallerProcess(claimed) || LkgWatchHostWindows.InstallerOwnsService())
            {
                RetryWithoutCharge(context, claimed, watch);
                return;
            }

            try
            {
                ClearPreviousDenial(store, lkg.ProductCode);
                var issuedUtc = DateTimeOffset.UtcNow;
                WriteGrant(store, new(AgentUpdateRollbackGrant.Schema, Guid.NewGuid(), rollbackId, watch.AttemptId,
                    watch.WatchedProductCode, lkg.ProductCode, lkg.Version, lkg.MsiSha256, issuedUtc, issuedUtc.AddHours(1), native.BootId));
                if (!SameAuthority(context.JournalStore.Read(), launch, watch.AttemptId))
                {
                    TryDeleteGrant(context);
                    return;
                }
                invocationStartedUtc = DateTimeOffset.UtcNow;
                process = Process.Start(start) ?? throw new InvalidOperationException("Windows Installer could not be started.");
            }
            catch
            {
                TryDeleteGrant(context);
                throw;
            }
        }

        using (process)
        {
            try
            {
                var started = new DateTimeOffset(process.StartTime.ToUniversalTime());
                invocationStartedUtc = started;
                Patch(context, launch, watch, before => before with { InstallerProcessId = process.Id, InstallerStartedUtc = started });
            }
            catch (Exception ex) when (LkgWatchHost.IsHostFailure(ex)) { context.Log("rollback_installer_receipt_unavailable"); }
            // The installer owns its lifetime even if its process receipt could not be recorded.
            process.WaitForExit();
            var invocationCompletedUtc = DateTimeOffset.UtcNow;
            TryDeleteGrant(context);
            CompleteLaunch(context, launch, watch, lkg, process.ExitCode, msiLogPath, invocationStartedUtc, invocationCompletedUtc);
        }
    }

    private static void CompleteLaunch(LkgWatchHostContext context, AgentUpdateJournal launch, AgentUpdateWatchRecord watch,
        AgentUpdateLkgRecord lkg, int exitCode, string msiLogPath, DateTimeOffset invocationStartedUtc, DateTimeOffset invocationCompletedUtc)
    {
        var current = context.JournalStore.Read();
        if (!SameAuthority(current, launch, watch.AttemptId)) return;
        if (exitCode is 0 or 3010)
        {
            var native = LkgWatchHostWindows.Observe();
            if (exitCode == 3010 && native.Service.CanonicalImagePendingRename)
            {
                Patch(context, current, watch, before => before with
                {
                    AlertCode = AgentUpdateErrorCodes.RebootRequired,
                    AlertAttemptId = before.RollbackAttemptId,
                    InstallerProcessId = null,
                    InstallerStartedUtc = null,
                });
                return;
            }
            if (VerifiedTarget(native, lkg, current.LifecycleGeneration))
                Finish(context, current, watch, AgentUpdateWatchOutcomes.RolledBack, AgentUpdateWatchJournal.PostCommitRollback, lkg);
            else
                RecordFailure(context, current, watch);
            return;
        }

        var failure = ClassifyFailure(context.Store, exitCode, msiLogPath, lkg.ProductCode, invocationStartedUtc, invocationCompletedUtc);
        if (failure.GrantRefusal is { } denial)
        {
            context.Log(denial.ReasonCode);
            if (denial.Disposition == AgentUpdateGrantRefusalDisposition.Retry)
                RetryWithoutCharge(context, current, watch);
            else
                Finish(context, current, WithAlert(watch, AgentUpdateWatchOutcomes.RollbackFailed, denial.ReasonCode),
                    AgentUpdateWatchOutcomes.RollbackFailed, AgentUpdateWatchJournal.RollbackFailed, null);
            return;
        }
        if (failure.Kind is AgentUpdateMsiFailureKind.Busy or AgentUpdateMsiFailureKind.Environment)
        {
            RetryWithoutCharge(context, current, watch);
            return;
        }
        RecordFailure(context, current, watch);
    }

    private static void RecordFailure(LkgWatchHostContext context, AgentUpdateJournal current, AgentUpdateWatchRecord watch)
    {
        var count = Math.Min(MaximumAttempts, current.RollbackAttemptCount + 1);
        if (count == MaximumAttempts || Expired(current, DateTimeOffset.UtcNow))
        {
            Finish(context, current, watch, AgentUpdateWatchOutcomes.RollbackFailed, AgentUpdateWatchJournal.RollbackFailed, null, count);
            return;
        }
        var now = DateTimeOffset.UtcNow;
        context.Log("rollback_installer_failed");
        Patch(context, current, watch, before => before with
        {
            RollbackAttemptCount = count,
            RollbackStartedUtc = now,
            InstallerProcessId = null,
            InstallerStartedUtc = null,
        });
    }

    private static void RetryWithoutCharge(LkgWatchHostContext context, AgentUpdateJournal current, AgentUpdateWatchRecord watch)
        => Patch(context, current, watch, before => before with
        {
            RollbackStartedUtc = null,
            InstallerProcessId = null,
            InstallerStartedUtc = null,
            AlertCode = null,
            AlertAttemptId = null,
        });

    private static (AgentUpdateMsiFailureKind Kind, AgentUpdateGrantRefusal? GrantRefusal) ClassifyFailure(
        AgentUpdateLkgStore store, int exitCode, string path, Guid targetProductCode,
        DateTimeOffset invocationStartedUtc, DateTimeOffset invocationCompletedUtc)
    {
        FileStream? log = null;
        try
        {
            AgentUpdateSecurity.ValidateProtectedPath(path, store.UpdatesRoot, allowMissing: false);
            log = File.OpenRead(path);
        }
        catch (Exception ex) when (LkgWatchHost.IsHostFailure(ex)) { }
        using (log)
            return AgentUpdateMsiFailure.ClassifyRollback(exitCode, log, store.UpdatesRoot, targetProductCode,
                invocationStartedUtc, invocationCompletedUtc);
    }

    private static void Finish(LkgWatchHostContext context, AgentUpdateJournal active, AgentUpdateWatchRecord watch,
        string outcome, string code, AgentUpdateLkgRecord? lkg, int? count = null)
    {
        var now = DateTimeOffset.UtcNow;
        var record = outcome == AgentUpdateWatchOutcomes.RolledBack ? watch with { Outcome = outcome } : WithAlert(watch, outcome, code);
        AgentUpdateWatchStore.Write(context.Store.UpdatesRoot, record);
        if (!Patch(context, active, watch, before =>
        {
            var pin = AgentUpdateWatchPolicy.PostCommitPin(before.FailedInstallSequence, watch.WatchedSequence);
            if (outcome == AgentUpdateWatchOutcomes.Superseded)
                return LkgWatchHostBinding.WithWatchOutcome(before, code, null, 0) with { FailedInstallSequence = pin };

            return before with
            {
                Phase = AgentUpdateStates.Failed,
                FailureCode = code,
                FailureAttemptId = before.AttemptId,
                FailureInstallerResultId = before.InstallerResult?.ResultId,
                WatchOutcomeCode = null,
                WatchOutcomeAttemptId = null,
                AlertCode = null,
                AlertAttemptId = null,
                InstallerProcessId = null,
                InstallerStartedUtc = null,
                RollbackAttemptCount = count ?? before.RollbackAttemptCount,
                FailedInstallSequence = pin,
                HealthyInstalledVersion = lkg?.Version,
                HealthyInstalledSequence = lkg?.ManifestSequence ?? 0,
                NextCheckUtc = lkg is null ? before.NextCheckUtc : now.AddHours(24) + AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6)),
            };
        })) return;
        TryDeleteGrant(context);
        context.Log(code);
        if (outcome == AgentUpdateWatchOutcomes.RollbackFailed)
            LkgWatchHostWindows.Restart(false, context.JournalStore.Read);
    }

    private static void CloseBeforeRollback(LkgWatchHostContext context, AgentUpdateWatchRecord watch, string outcome, string code)
    {
        var record = WithAlert(watch, outcome, code);
        AgentUpdateWatchStore.Write(context.Store.UpdatesRoot, record);
        LkgWatchHostBinding.CloseWithoutPromotion(context, record, code);
    }

    private static AgentUpdateWatchRecord WithAlert(AgentUpdateWatchRecord watch, string outcome, string code)
        => watch with { Outcome = outcome, Alerts = watch.Alerts.Contains(code, StringComparer.Ordinal) ? watch.Alerts : [.. watch.Alerts, code] };

    private static bool Patch(LkgWatchHostContext context, AgentUpdateJournal expected, AgentUpdateWatchRecord watch,
        Func<AgentUpdateJournal, AgentUpdateJournal> change)
        => AgentUpdateJournalPatch.TryApply(context.JournalStore, watch.AttemptId, expected.Phase,
            before => SameAuthority(before, expected, watch.AttemptId) ? change(before) : null);

    internal static bool SameAuthority(AgentUpdateJournal current, AgentUpdateJournal expected, string attempt)
        => current.Phase is AgentUpdateWatchJournal.CommittedWatch or AgentUpdateWatchJournal.RollingBack &&
            current.Phase == expected.Phase && LkgWatchHostBinding.BindsWatch(current, attempt) &&
            LkgWatchHostBinding.BindsWatch(expected, attempt) && current.LifecycleGeneration == expected.LifecycleGeneration &&
            current.WatchRequestedUtc == expected.WatchRequestedUtc &&
            current.RollbackAttemptId == expected.RollbackAttemptId && current.RollbackStartedUtc == expected.RollbackStartedUtc &&
            current.RollbackFirstUtc == expected.RollbackFirstUtc && current.RollbackAttemptCount == expected.RollbackAttemptCount &&
            (current.Phase != AgentUpdateWatchJournal.RollingBack || AgentUpdateSecurity.IsSafeAttemptId(current.RollbackAttemptId));

    private static bool MatchesWatchedRuntime(LkgWatchHostObservation native, AgentUpdateWatchRecord watch, long generation)
        => native.Generation == generation && native.InstalledVersion == watch.WatchedVersion &&
            native.Identity is { } identity && identity.Version == watch.WatchedVersion && identity.ProductCode == watch.WatchedProductCode &&
            !native.Service.InstallerMutexHeld && !native.Service.CanonicalImagePendingRename;

    private static bool VerifiedTarget(LkgWatchHostObservation native, AgentUpdateLkgRecord lkg, long generation)
        => native.Generation == generation && native.InstalledVersion == lkg.Version && !native.Service.CanonicalImagePendingRename &&
            native.Identity is { } identity && identity.Version == lkg.Version && identity.ProductCode == lkg.ProductCode &&
            LkgWatchHost.HashMatches(identity.ServiceExeSha256, lkg.ServiceExeSha256) &&
            LkgWatchHostWindows.HashCanonicalService(identity) is { } hash && LkgWatchHost.HashMatches(lkg.ServiceExeSha256, hash);

    private static bool IsThirdVersion(string? installed, AgentUpdateWatchRecord watch, bool rollingBack)
        => AgentUpdateManifestValidator.IsReleaseVersion(installed) && installed != watch.WatchedVersion &&
            (!rollingBack || installed != watch.ReplacedVersion);

    private static bool Expired(AgentUpdateJournal active, DateTimeOffset now)
        => active.RollbackAttemptCount >= MaximumAttempts || active.RollbackFirstUtc is { } first && now - first >= RetryLimit;

    private static void WriteGrant(AgentUpdateLkgStore store, AgentUpdateRollbackGrantRecord grant)
    {
        DeleteGrant(store);
        var path = Path.Combine(store.Root, AgentUpdateRollbackGrant.FileName);
        var staged = Path.Combine(store.Root, ".rollback-grant.tmp");
        AgentUpdateSecurity.ValidateProtectedPath(staged, store.UpdatesRoot, allowMissing: true);
        File.Delete(staged);
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm(AgentUpdateRollbackGrant.Descriptor);
        var created = false;
        try
        {
            using (var stream = FileSystemAclExtensions.Create(new FileInfo(staged), FileMode.CreateNew,
                FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.WriteThrough, security))
            {
                created = true;
                if (!AgentUpdateRollbackGrant.HasRequiredDescriptor(AgentUpdateRollbackGrant.ReadOpenedGrantDescriptor(stream)))
                    throw new InvalidOperationException("Rollback grant descriptor could not be verified.");
                JsonSerializer.Serialize(stream, grant, AgentUpdateLkgStore.RecordJson);
                stream.Flush(flushToDisk: true);
            }
            File.Move(staged, path);
        }
        finally { if (created) File.Delete(staged); }
    }

    private static void DeleteGrant(AgentUpdateLkgStore store)
    {
        var grant = Path.Combine(store.Root, AgentUpdateRollbackGrant.FileName);
        AgentUpdateSecurity.ValidateProtectedPath(grant, store.UpdatesRoot, allowMissing: true);
        File.Delete(grant);
    }

    private static void TryDeleteGrant(LkgWatchHostContext context)
    {
        try { DeleteGrant(context.Store); }
        catch (Exception ex) when (LkgWatchHost.IsHostFailure(ex)) { context.Log("rollback_grant_cleanup_failed"); }
    }

    private static void ClearPreviousDenial(AgentUpdateLkgStore store, Guid targetProductCode)
    {
        var directory = Path.Combine(store.UpdatesRoot, AgentUpdaterContract.InstallerTransactionsDirectoryName);
        var receipt = Path.Combine(directory, $"{targetProductCode:N}.rollback-grant.json");
        AgentUpdateSecurity.ValidateProtectedPath(receipt, store.UpdatesRoot, allowMissing: true);
        if (Directory.Exists(directory)) File.Delete(receipt);
    }

    private static bool InstalledTargetProduct(Guid productCode)
    {
        var state = MsiQueryProductState(productCode.ToString("B"));
        return state switch
        {
            5 => true,   // INSTALLSTATE_DEFAULT
            -1 => false, // INSTALLSTATE_UNKNOWN
            2 => false,  // INSTALLSTATE_ABSENT
            _ => throw new InvalidOperationException("Windows Installer target product state is ambiguous."),
        };
    }

    [DllImport("msi.dll", EntryPoint = "MsiQueryProductStateW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int MsiQueryProductState(string productCode);
}
