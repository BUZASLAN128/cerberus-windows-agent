using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using Cerberus.Agent.Core;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Updater;

internal sealed record LkgWatchHostWork(
    IReadOnlyList<string> ManifestKeys,
    Action<string, string> VerifyHostArtifact,
    Func<LkgWatchHostContext, Func<LkgWatchHostTick>?> StartSampling,
    Action<LkgWatchHostContext, AgentUpdateWatchRecord> CloseWithoutPromotion,
    Action<LkgWatchHostContext, AgentUpdateWatchRecord> Promote,
    Action<LkgWatchHostContext> ResumePromotion,
    Action<AgentUpdateLkgStore> CleanupRetired,
    Action<LkgWatchHostContext, AgentUpdateWatchRecord> Rollback);

internal sealed record LkgWatchHostContext(AgentUpdateLkgStore Store, AgentUpdateJournalStore JournalStore,
    AgentUpdateJournal? Journal, AgentUpdateWatchRecord? Watch, AgentUpdatePlan? Plan, bool InvokedByScm,
    bool InstalledManifestVerified, Action<string> Log);

internal sealed record LkgWatchHostTick(AgentUpdateWatchRecord Record, bool ShouldPersist, AgentUpdateWatchOutcome Decision);

internal sealed record LkgWatchHostSnapshot(AgentUpdateJournal? Journal, AgentUpdateWatchRecord? Watch,
    bool UnknownPhase, bool PromotionPending, bool HasRetiredFiles)
{
    public bool InstalledManifestVerified { get; init; }

    public bool HasWork => UnknownPhase || PromotionPending || HasRetiredFiles || Watch?.Outcome == AgentUpdateWatchOutcomes.Open ||
        Journal?.Phase is AgentUpdateWatchJournal.CommittedWatch or AgentUpdateWatchJournal.RollingBack;
}

internal sealed record LkgWatchHostOperations(
    Func<bool> HasAuthority,
    Action<bool> Restart,
    Action VerifyHost,
    Func<LkgWatchHostSnapshot> ReadSnapshot,
    Func<IDisposable?> TryLock,
    Func<LkgWatchHostSnapshot, LkgSignedFloor.Inspection?> InspectFloor,
    Action<LkgSignedFloor.Candidate> ApplyFloor,
    Action VerifyTask,
    Action<LkgWatchHostSnapshot, bool> Act,
    Action<AgentUpdateWatchRecord> WriteWatch,
    Action<string> Log);

internal static class LkgWatchHost
{
    internal static int Run(AgentUpdateWatchHostArgs args, LkgWatchHostWork work)
    {
        var store = new AgentUpdateLkgStore(AgentUpdateSecurity.DefaultPrivilegedRoot);
        var journal = new AgentUpdateJournalStore(store.UpdatesRoot);
        var log = new LkgHostLog(store.UpdatesRoot);
        return Run(args, new LkgWatchHostOperations(
            () => AgentBuildProfile.IsServer && AgentUpdateSecurity.IsLocalSystem(),
            scm => LkgWatchHostWindows.Restart(scm, () => TryReadRawJournal(store.UpdatesRoot)),
            () => VerifySelf(store, work.VerifyHostArtifact),
            () => ReadSnapshot(store, journal),
            () => TryLock(store),
            snapshot => LkgSignedFloor.Inspect(store.UpdatesRoot,
                LkgSignedFloor.ReadPlan(store.UpdatesRoot, snapshot.Journal?.AttemptId),
                LkgWatchHostWindows.ReadInstalledVersion(), work.ManifestKeys),
            candidate => LkgSignedFloor.Apply(store.UpdatesRoot, candidate, DateTimeOffset.UtcNow),
            AgentUpdateWatchTask.VerifyAndRepair,
            (snapshot, scm) => Act(store, journal, snapshot, scm, log.Write, work),
            watch => AgentUpdateWatchStore.Write(store.UpdatesRoot, watch),
            log.Write));
    }

    internal static int Run(AgentUpdateWatchHostArgs args, LkgWatchHostOperations operations)
    {
        if (args.Mode is not (AgentUpdateWatchHostMode.Watch or AgentUpdateWatchHostMode.ScmFailure) || !operations.HasAuthority())
            return 2;

        var invokedByScm = args.Mode == AgentUpdateWatchHostMode.ScmFailure;
        try { operations.Restart(invokedByScm); }
        catch (Exception ex) when (IsHostFailure(ex)) { }

        try { operations.VerifyHost(); }
        catch (Exception ex) when (IsHostFailure(ex))
        {
            operations.Log("watch_host_self_check_failed");
            return 2;
        }

        var acting = false;
        try
        {
            var state = operations.ReadSnapshot();
            acting = state.HasWork;
            if (!acting && operations.InspectFloor(state)?.Pending is null)
                return 0;

            using var gate = operations.TryLock();
            if (gate is null)
                return 0;

            // Journal and promotion state may change while acquiring the host lock.
            state = operations.ReadSnapshot();
            acting = state.HasWork;
            if (state.UnknownPhase)
            {
                operations.Log(AgentUpdateWatchJournal.UnknownPhaseAlert);
                if (state.Watch is { } watch && state.Journal?.AttemptId == watch.AttemptId &&
                    !watch.Alerts.Contains(AgentUpdateWatchJournal.UnknownPhaseAlert, StringComparer.Ordinal))
                    operations.WriteWatch(watch with { Alerts = [.. watch.Alerts, AgentUpdateWatchJournal.UnknownPhaseAlert] });
                return 0;
            }

            LkgSignedFloor.Inspection? floor = null;
            try { floor = operations.InspectFloor(state); }
            catch (Exception ex) when (acting && IsHostFailure(ex)) { operations.Log("watch_signed_floor_unavailable"); }

            if (floor?.Pending is { } candidate)
                operations.ApplyFloor(candidate);
            if (!acting)
                return 0;

            operations.VerifyTask();
            operations.Act(state with { InstalledManifestVerified = floor is not null }, invokedByScm);
            return 0;
        }
        catch (Exception ex) when (IsHostFailure(ex))
        {
            if (acting) operations.Log("watch_host_action_failed");
            return 2;
        }
    }

    private static void Act(AgentUpdateLkgStore store, AgentUpdateJournalStore journalStore, LkgWatchHostSnapshot state,
        bool invokedByScm, Action<string> log, LkgWatchHostWork work)
    {
        AgentUpdatePlan? plan = null;
        try { plan = LkgSignedFloor.ReadPlan(store.UpdatesRoot, state.Journal?.AttemptId); }
        catch (Exception ex) when (IsHostFailure(ex)) { }
        var context = new LkgWatchHostContext(store, journalStore, state.Journal, state.Watch, plan, invokedByScm,
            state.InstalledManifestVerified, log);
        if (state.PromotionPending)
        {
            work.ResumePromotion(context);
            return;
        }
        if (state.HasRetiredFiles)
            work.CleanupRetired(store);

        if (state.Journal?.Phase == AgentUpdateWatchJournal.RollingBack)
        {
            if (state.Watch is { } rollbackWatch && LkgWatchHostBinding.BindsWatch(state.Journal, rollbackWatch.AttemptId))
                work.Rollback(context, rollbackWatch);
            return;
        }

        var committed = state.Journal?.Phase == AgentUpdateWatchJournal.CommittedWatch;
        var attempt = committed ? state.Journal!.AttemptId : state.Watch?.AttemptId;
        if (!AgentUpdateSecurity.IsSafeAttemptId(attempt) || (!committed && state.Watch?.Outcome != AgentUpdateWatchOutcomes.Open))
            return;

        if (state.Watch is { } existing && existing.AttemptId == attempt && existing.Outcome != AgentUpdateWatchOutcomes.Open)
        {
            if (existing.Outcome == AgentUpdateWatchOutcomes.Passed && committed && state.InstalledManifestVerified && PlanMatches(plan, existing))
                work.Promote(context, existing);
            if (committed && existing.Outcome is (AgentUpdateWatchOutcomes.ForwardOnlyFailed or
                AgentUpdateWatchOutcomes.Superseded or AgentUpdateWatchOutcomes.Inconclusive))
                work.CloseWithoutPromotion(context, existing);
            return;
        }

        if (work.StartSampling(context) is not { } sample)
            return;
        while (true)
        {
            var tick = sample();
            if (tick.Record.AttemptId != attempt)
                throw new InvalidOperationException("Watch sampling changed its attempt binding.");
            if (tick.ShouldPersist || tick.Decision != AgentUpdateWatchOutcome.Open)
                AgentUpdateWatchStore.Write(store.UpdatesRoot, tick.Record);

            switch (tick.Decision)
            {
                case AgentUpdateWatchOutcome.Open:
                    Thread.Sleep(TimeSpan.FromSeconds(2));
                    continue;
                case AgentUpdateWatchOutcome.Passed when committed && state.InstalledManifestVerified && PlanMatches(plan, tick.Record):
                    work.Promote(context, tick.Record);
                    break;
                case AgentUpdateWatchOutcome.RollbackPending when committed:
                    work.Rollback(context, tick.Record);
                    break;
                case AgentUpdateWatchOutcome.ForwardOnlyFailed or AgentUpdateWatchOutcome.Superseded or AgentUpdateWatchOutcome.Inconclusive:
                    work.CloseWithoutPromotion(context, tick.Record);
                    break;
            }
            return;
        }
    }

    private static bool PlanMatches(AgentUpdatePlan? plan, AgentUpdateWatchRecord watch)
        => plan is not null && plan.AttemptId == watch.AttemptId && plan.Version == watch.WatchedVersion && plan.Sequence == watch.WatchedSequence;

    internal static FileStream? TryLock(AgentUpdateLkgStore store)
    {
        var path = Path.Combine(store.Root, AgentUpdateLkgStore.LockFileName);
        try
        {
            AgentUpdateSecurity.ValidateTrustedPath(path, store.UpdatesRoot, allowMissing: false);
            return new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException ex) when (ex is FileNotFoundException or DirectoryNotFoundException || (ex.HResult & 0xFFFF) is 32 or 33)
        {
            return null;
        }
    }

    private static void VerifySelf(AgentUpdateLkgStore store, Action<string, string> verifyArtifact)
    {
        if (!string.Equals(Environment.ProcessPath, store.HostPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The update watch host must run from the protected LKG image.");
        AgentUpdateSecurity.ValidateProtectedTree(store.Root);
        var host = store.ReadHost() ?? throw new InvalidOperationException("The watch host metadata is missing.");
        var promotion = store.ReadPromotion();
        using var image = new FileStream(store.HostPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var hash = Convert.ToHexStringLower(SHA256.HashData(image));
        if (!HashMatches(host.UpdaterSha256, hash) &&
            (promotion is null || !HashMatches(promotion.OldUpdaterSha256, hash) && !HashMatches(promotion.NewUpdaterSha256, hash)))
            throw new InvalidOperationException("The update watch host hash does not match protected metadata.");

        verifyArtifact(store.HostPath, hash);
    }

    private static LkgWatchHostSnapshot ReadSnapshot(AgentUpdateLkgStore store, AgentUpdateJournalStore journal)
    {
        var raw = ReadRawJournal(store.UpdatesRoot);
        var unknown = raw is not null && !AgentUpdateJournalStore.KnownPhase(raw.Phase);
        AgentUpdateWatchRecord? watch = null;
        try { watch = AgentUpdateWatchStore.Read(store.UpdatesRoot); }
        catch (Exception ex) when (unknown && IsHostFailure(ex)) { }
        if (unknown)
            return new(raw, watch, true, false, false);

        var active = raw is null ? null : journal.Read();
        if (active is not null && !AgentUpdateJournalStore.KnownPhase(active.Phase))
            throw new InvalidOperationException("The update journal changed while reading watch state.");
        return new(active, watch, false, store.ReadPromotion() is not null,
            Directory.EnumerateFiles(store.Root, "retired-*", SearchOption.TopDirectoryOnly).Any());
    }

    private static AgentUpdateJournal? TryReadRawJournal(string root)
    {
        try { return ReadRawJournal(root); }
        catch (Exception ex) when (IsHostFailure(ex)) { return null; }
    }

    private static AgentUpdateJournal? ReadRawJournal(string root)
    {
        var value = AgentUpdateDurableFile.Read<AgentUpdateJournal>(Path.Combine(root, "transaction.json"), root);
        if (value is not null && (value.SchemaVersion != AgentUpdaterContract.JournalSchema || value.Revision < 0 ||
            value.Phase is null || !AgentUpdateErrorCodes.IsCode(value.Phase) ||
            value.AttemptId is not null && !AgentUpdateSecurity.IsSafeAttemptId(value.AttemptId)))
            throw new InvalidOperationException("The update watch journal envelope is invalid.");
        return value;
    }

    internal static bool HashMatches(string? expected, string actual) => string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase);

    internal static bool IsHostFailure(Exception ex) => ex is IOException or InvalidOperationException or UnauthorizedAccessException or
        ArgumentException or Win32Exception or COMException or SecurityException or CryptographicException or JsonException;
}

internal sealed record LkgWatchRuntimeIdentity(string Version, Guid ProductCode, string ServiceExeSha256, string RuntimeRoot)
{
    public string ServicePath => Path.Combine(RuntimeRoot, "Cerberus.Agent.Service.exe");
}

internal sealed record LkgWatchHostObservation(string BootId, long TickCount, DateTimeOffset NowUtc,
    string? InstalledVersion, long? Generation, AgentUpdateWatchSample Service, LkgWatchRuntimeIdentity? Identity,
    bool? ProcessImageCanonical, bool? ServiceImageCanonical, long? ExeSize, DateTimeOffset? ExeMtime);

internal static class LkgWatchHostWindows
{
    private const uint QueryStatus = 0x0004;
    private const uint Start = 0x0010;
    private const int ServiceAlreadyRunning = 1056;

    internal static void Restart(bool invokedByScm, Func<AgentUpdateJournal?> readJournal)
    {
        AgentUpdateWatchRestart Decide()
        {
            var journal = readJournal();
            var owner = HasInstallerProcess(journal);
            var sample = ReadStatus(bootId: "", includeProcessStart: false);
            return AgentUpdateWatchPolicy.RestartDecision(sample, invokedByScm, owner, InstallerOwnsService());
        }

        var decision = Decide();
        if (decision == AgentUpdateWatchRestart.WaitThenStart)
        {
            Thread.Sleep(TimeSpan.FromSeconds(60));
            decision = Decide();
        }
        if (decision != AgentUpdateWatchRestart.None)
        {
            using var manager = OpenManager();
            using var service = OpenService(manager, Start);
            if (!StartServiceW(service, 0, IntPtr.Zero) && Marshal.GetLastWin32Error() != ServiceAlreadyRunning)
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    internal static LkgWatchHostObservation Observe()
    {
        var boot = AgentUpdateBootIdentity.Read();
        var observed = Environment.TickCount64;
        var now = DateTimeOffset.UtcNow;
        var version = ReadInstalledVersion();
        var runtime = ReadRuntimeIdentity();
        var lifecycle = AgentLifecycleFile.ReadProduction();
        long? generation = lifecycle.ReasonCode == "lifecycle_state_invalid" ? null : lifecycle.Generation;
        var service = ReadStatus(boot, includeProcessStart: true);
        if (runtime is null)
            return new(boot, observed, now, version, generation, service with { InstallerMutexHeld = InstallerOwnsService() }, null, null, null, null, null);

        using var serviceKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{AgentInstallIdentity.ServiceName}");
        var imagePath = AgentServiceImagePath.ExtractExecutablePath(serviceKey?.GetValue("ImagePath") as string);
        var canonical = imagePath is not null && AgentServiceImagePath.Matches(imagePath, runtime.ServicePath);
        var imageInfo = new FileInfo(runtime.ServicePath);
        var exists = imageInfo.Exists;
        return new(boot, observed, now, version, generation, service with
        {
            InstallerMutexHeld = InstallerOwnsService(),
            CanonicalImagePendingRename = CanonicalImagePendingRename(runtime.ServicePath),
        }, runtime, ReadProcessImageMatch(service, runtime.ServicePath), canonical,
            exists ? imageInfo.Length : null, exists ? new DateTimeOffset(imageInfo.LastWriteTimeUtc) : null);
    }

    internal static string? ReadInstalledVersion()
    {
        using var key = Registry.LocalMachine.OpenSubKey(AgentInstallIdentity.RegistryPath);
        return key?.GetValue("productVersion") as string;
    }

    internal static LkgWatchRuntimeIdentity? ReadRuntimeIdentity()
    {
        using var key = Registry.LocalMachine.OpenSubKey(AgentInstallIdentity.RegistryPath);
        var version = key?.GetValue("productVersion") as string;
        var hash = key?.GetValue("serviceExeSha256") as string;
        if (key is null || !AgentUpdateManifestValidator.IsReleaseVersion(version) || !AgentUpdateManifestValidator.IsSha256(hash) ||
            !Guid.TryParse(key.GetValue("ProductCode") as string, out var productCode) || productCode == Guid.Empty)
            return null;

        var runtimeRoot = AgentUpdateSecurity.ResolveRegisteredRuntimeRoot(key.GetValue("runtimeRoot") as string, key.GetValue("installRoot") as string);
        var canonical = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cerberus", "Server Agent", "app");
        if (!string.Equals(runtimeRoot, canonical, StringComparison.OrdinalIgnoreCase))
            return null;
        AgentUpdateSecurity.ValidateProtectedPath(runtimeRoot, runtimeRoot, allowMissing: false);
        return new(version!, productCode, hash!, runtimeRoot);
    }

    internal static string? HashCanonicalService(LkgWatchRuntimeIdentity? runtime)
    {
        if (runtime is null) return null;
        try
        {
            AgentUpdateSecurity.ValidateInstalledServiceSource(runtime.ServicePath, runtime.RuntimeRoot);
            using var stream = new FileStream(runtime.ServicePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }
        catch (Exception ex) when (LkgWatchHost.IsHostFailure(ex)) { return null; }
    }

    private static bool CanonicalImagePendingRename(string path)
    {
        using var manager = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager");
        var paths = manager?.GetValue("PendingFileRenameOperations") as string[] ?? [];
        return paths.Any(value => value.TrimStart('!').Equals(@"\??\" + path, StringComparison.OrdinalIgnoreCase) ||
            value.TrimStart('!').Equals(path, StringComparison.OrdinalIgnoreCase));
    }

    internal static bool HasInstallerProcess(AgentUpdateJournal? journal)
        => IsAlive(journal?.RunnerProcessId, journal?.RunnerStartedUtc) || IsAlive(journal?.InstallerProcessId, journal?.InstallerStartedUtc);

    internal static bool InstallerOwnsService()
    {
        try
        {
            using var mutex = Mutex.OpenExisting(@"Global\_MSIExecute");
            return true;
        }
        catch (WaitHandleCannotBeOpenedException) { return false; }
        catch (UnauthorizedAccessException) { return true; }
    }

    private static bool IsAlive(int? pid, DateTimeOffset? startedUtc)
    {
        if (pid is not > 0 || startedUtc is null) return false;
        try
        {
            using var process = Process.GetProcessById(pid.Value);
            return !process.HasExited && new DateTimeOffset(process.StartTime.ToUniversalTime()) == startedUtc;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception) { return false; }
    }

    private static bool? ReadProcessImageMatch(AgentUpdateWatchSample sample, string canonical)
    {
        if (sample.ProcessId is not > 0 || sample.ProcessStartedUtc is null) return null;
        try
        {
            using var process = Process.GetProcessById(sample.ProcessId.Value);
            if (process.HasExited || new DateTimeOffset(process.StartTime.ToUniversalTime()) != sample.ProcessStartedUtc)
                return null;
            var image = process.MainModule?.FileName;
            return image is null ? null : AgentServiceImagePath.Matches(image, canonical);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception) { return null; }
    }

    private static AgentUpdateWatchSample ReadStatus(string bootId, bool includeProcessStart)
    {
        using var manager = OpenManager();
        using var service = OpenService(manager, QueryStatus);
        if (!QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatusProcess>(), out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        int? pid = status.ProcessId is > 0 and <= int.MaxValue ? (int)status.ProcessId : null;
        DateTimeOffset? start = null;
        if (includeProcessStart && pid is { } id)
        {
            try
            {
                using var process = Process.GetProcessById(id);
                if (!process.HasExited) start = new DateTimeOffset(process.StartTime.ToUniversalTime());
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception) { }
        }

        var state = status.CurrentState switch
        {
            1 => AgentUpdateWatchServiceState.Stopped,
            2 => AgentUpdateWatchServiceState.Starting,
            3 => AgentUpdateWatchServiceState.Stopping,
            4 => AgentUpdateWatchServiceState.Running,
            _ => AgentUpdateWatchServiceState.Other,
        };
        return new(bootId, pid, start, state, unchecked((int)status.Win32Exit), unchecked((int)status.ServiceExit), false, false, false);
    }

    private static ServiceHandle OpenManager() => RequireHandle(OpenSCManagerW(null, null, 1));
    private static ServiceHandle OpenService(ServiceHandle manager, uint access)
        => RequireHandle(OpenServiceW(manager, AgentInstallIdentity.ServiceName, access));

    private static ServiceHandle RequireHandle(ServiceHandle handle)
    {
        if (!handle.IsInvalid) return handle;
        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw new Win32Exception(error);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint Type, CurrentState, ControlsAccepted, Win32Exit, ServiceExit, CheckPoint, WaitHint, ProcessId, Flags;
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(ownsHandle: true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern ServiceHandle OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern ServiceHandle OpenServiceW(ServiceHandle manager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatusProcess status, int size, out int needed);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool StartServiceW(ServiceHandle service, int argumentCount, IntPtr arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}
