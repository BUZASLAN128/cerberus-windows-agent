using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Microsoft.Win32;

namespace Cerberus.Agent.Updater;

internal static class Program
{
    private const int MsiBusyExitCode = 1618;
    private const int MaxMsiBusyRetries = 3;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static int Main(string[] args)
    {
        var log = UpdaterLog.Create();
        log.Write("Cerberus Agent updater starting.");
        if (!AgentUpdateSecurity.IsLocalSystem())
        {
            log.Write("Updater denied: process is not LocalSystem.");
            return 2;
        }

        if (!TryReadAttemptId(args, out var attemptId))
        {
            log.Write("Updater denied: attempt identifier is missing or invalid.");
            return 2;
        }

        ClosedApplications closedApplications = new(false, []);
        AgentUpdatePlan? plan = null;
        try
        {
            var root = AgentUpdateStager.DefaultStagingRoot;
            using var operationLock = AgentUpdateSecurity.AcquireGlobalLock(root);
            var attemptDirectory = AgentUpdateSecurity.ResolveAttemptDirectory(root, attemptId);
            plan = LoadAndValidateAttempt(attemptId, attemptDirectory, log);
            var trust = AgentUpdateTrustFactory.BuildTrust();
            var manifest = LoadAndValidateManifest(plan, attemptDirectory, trust);
            ValidateAttemptArtifact(plan, manifest, attemptDirectory, root, trust);
            ValidateCanonicalServiceLayout();

            StopServiceChecked();
            closedApplications = CloseAgentUiApplications();

            var msiLogPath = log.CreateSiblingLogPath("msiexec");
            var installerRun = RunMsiexecWithBusyRetry(plan, msiLogPath, log);
            var exitCode = installerRun.ExitCode;
            var installerResult = AgentUpdateInstallerResult.FromMsiExitCode(
                exitCode,
                exitCode == 0 || exitCode == 3010 ? null : "msiexec failed.",
                msiLogPath) with
            {
                AttemptId = plan.AttemptId,
                RetryCount = installerRun.RetryCount,
            };
            if (!string.Equals(installerResult.State, AgentUpdateStates.Applied, StringComparison.Ordinal))
            {
                var failedResult = installerResult with { Quarantined = true };
                WriteInstallerResult(failedResult, log);
                QuarantineAttempt(plan, log);
                TryStartService(log);
                TryRestartAgentUi(closedApplications, log);
                return exitCode == 0 ? 1 : exitCode;
            }

            WriteInstallerResult(installerResult, log);
            ValidateCanonicalServiceLayout();
            StartServiceChecked();
            WaitForLocalHealthGate(TimeSpan.FromSeconds(60));
            WriteCurrentStateFromPlan(plan, installerResult, log);
            TryRestartAgentUi(closedApplications, log);
            log.Write("Cerberus Agent updater completed.");
            return 0;
        }
        catch (Exception ex)
        {
            var safeMessage = AgentUpdateState.SanitizeMessage(ex.Message);
            log.Write($"Updater failed: {ex.GetType().Name}: {safeMessage}");
            var result = AgentUpdateInstallerResult.Failure(new InvalidOperationException(safeMessage)) with
            {
                AttemptId = plan?.AttemptId ?? attemptId,
                Quarantined = plan is not null,
            };
            WriteInstallerResult(result, log);
            if (plan is not null)
                QuarantineAttempt(plan, log);
            TryStartService(log);
            TryRestartAgentUi(closedApplications, log);
            return 1;
        }
    }

    private static bool TryReadAttemptId(string[]? args, out string attemptId)
    {
        attemptId = "";
        if (args is null || args.Length != 2 || !string.Equals(args[0], "--attempt", StringComparison.Ordinal))
            return false;
        if (!AgentUpdateSecurity.IsSafeAttemptId(args[1]))
            return false;
        attemptId = args[1];
        return true;
    }

    private static AgentUpdatePlan LoadAndValidateAttempt(string attemptId, string attemptDirectory, UpdaterLog log)
    {
        var planPath = Path.Combine(attemptDirectory, AgentUpdateSecurity.PlanFileName);
        AgentUpdateSecurity.ValidateTrustedPath(planPath, AgentUpdateStager.DefaultStagingRoot, allowMissing: false);
        var raw = File.ReadAllText(planPath);
        var plan = JsonSerializer.Deserialize<AgentUpdatePlan>(raw, JsonOptions)
            ?? throw new InvalidOperationException("Update plan is invalid.");
        if (!string.Equals(plan.SchemaVersion, "agent.update.plan.v2", StringComparison.Ordinal) ||
            !string.Equals(plan.AttemptId, attemptId, StringComparison.Ordinal) ||
            !string.Equals(plan.ArtifactKind, "msi", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFullPath(plan.ArtifactPath), Path.Combine(attemptDirectory, AgentUpdateSecurity.ArtifactFileName), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update plan binding is invalid.");
        if (string.IsNullOrWhiteSpace(plan.ManifestPath) ||
            !string.Equals(Path.GetFullPath(plan.ManifestPath), Path.Combine(attemptDirectory, AgentUpdateSecurity.ManifestFileName), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update manifest binding is invalid.");
        log.Write($"Updater attempt loaded: attempt={attemptId}; version={plan.Version}; sequence={plan.Sequence}.");
        return plan;
    }

    private static AgentUpdateManifest LoadAndValidateManifest(
        AgentUpdatePlan plan,
        string attemptDirectory,
        AgentUpdateTrust trust)
    {
        var manifestPath = Path.Combine(attemptDirectory, AgentUpdateSecurity.ManifestFileName);
        AgentUpdateSecurity.ValidateTrustedPath(manifestPath, AgentUpdateStager.DefaultStagingRoot, allowMissing: false);
        var manifestJson = File.ReadAllText(manifestPath);
        var manifest = AgentUpdateManifestValidator.ParseAndValidateJson(
            manifestJson,
            trust.ManifestPublicKeyPems,
            trust.ExpectedChannel,
            trust.AllowedArtifactPrefixes,
            currentVersion: trust.CurrentVersion,
            allowRollbackManifest: false,
            allowChannelDowngrade: false);
        if (trust.RequireManifestV2 && !manifest.IsV2)
            throw new InvalidOperationException("Update manifest v2 is required before installation.");
        if (!manifest.IsV2 && AgentUpdateSequenceStore.ReadHighest(AgentUpdateStager.DefaultStagingRoot) > 0)
            throw new InvalidOperationException("Legacy update manifest fallback is disabled after v2 trust was accepted.");
        ValidateManifestSignerIdentity(manifest, trust);
        if (manifest.IsV2 && plan.Sequence != manifest.Sequence)
            throw new InvalidOperationException("Update plan sequence does not match the manifest.");
        if (!string.Equals(plan.ExpiresAtUtc, manifest.ExpiresAtUtc, StringComparison.Ordinal) ||
            !string.Equals(plan.SignerKeyIdentity, manifest.EffectiveSignerKeyIdentity, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update plan trust metadata does not match the manifest.");
        if (!string.Equals(plan.Version, manifest.Version, StringComparison.Ordinal) ||
            !string.Equals(plan.Channel, manifest.Channel, StringComparison.Ordinal) ||
            !string.Equals(plan.Sha256, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update plan does not match the manifest.");
        if (manifest.ArtifactLength is not null && plan.ArtifactLength != manifest.ArtifactLength)
            throw new InvalidOperationException("Update plan length does not match the manifest.");
        if (manifest.IsV2 && AgentUpdateSequenceStore.ReadHighest(AgentUpdateStager.DefaultStagingRoot) < manifest.Sequence)
            throw new InvalidOperationException("Update manifest sequence state is not committed.");
        if (AgentVersionComparer.CompareReleaseCore(manifest.Version, trust.CurrentVersion) is <= 0)
            throw new InvalidOperationException("Post-commit downgrade or replay was denied.");
        return manifest;
    }

    private static void ValidateManifestSignerIdentity(AgentUpdateManifest manifest, AgentUpdateTrust trust)
    {
        var expected = trust.AllowedSignerKeyIdentity?.Trim();
        var actual = manifest.EffectiveSignerKeyIdentity;
        if (string.IsNullOrWhiteSpace(expected))
        {
            if (!string.IsNullOrWhiteSpace(actual))
                throw new InvalidOperationException("Update manifest signer identity is not embedded in this build.");
            return;
        }

        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update manifest signer identity does not match this build.");
    }

    private static void ValidateAttemptArtifact(
        AgentUpdatePlan plan,
        AgentUpdateManifest manifest,
        string attemptDirectory,
        string root,
        AgentUpdateTrust trust)
    {
        var artifactPath = Path.Combine(attemptDirectory, AgentUpdateSecurity.ArtifactFileName);
        AgentUpdateSecurity.ValidateTrustedPath(artifactPath, root, allowMissing: false);
        var info = new FileInfo(artifactPath);
        if (info.Length <= 0 || info.Length > trust.MaxArtifactBytes)
            throw new InvalidOperationException("Update artifact length is invalid.");
        if (manifest.ArtifactLength is not null && info.Length != manifest.ArtifactLength.Value)
            throw new InvalidOperationException("Update artifact length does not match the manifest.");

        using var stream = File.OpenRead(artifactPath);
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
        if (!string.Equals(hash, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update artifact checksum mismatch.");

        AuthenticodeVerifier.Verify(
            artifactPath,
            trust.ExpectedChannel,
            trust.AllowedSignerKeyIdentity,
            trust.AllowUnsignedDevBuild);
    }

    private static (int ExitCode, int RetryCount) RunMsiexecWithBusyRetry(AgentUpdatePlan plan, string msiLogPath, UpdaterLog log)
    {
        var retries = ReadDurableRetryCount(plan, log);
        var retryAfter = ReadDurableRetryAfter(plan, log);
        if (retryAfter > DateTimeOffset.UtcNow)
            Thread.Sleep(retryAfter - DateTimeOffset.UtcNow);

        if (retries >= MaxMsiBusyRetries)
            return (MsiBusyExitCode, retries);

        while (true)
        {
            var exitCode = RunMsiexec(plan, msiLogPath, log);
            if (exitCode != MsiBusyExitCode || retries >= MaxMsiBusyRetries - 1)
                return (exitCode, retries);

            retries++;
            var delay = TimeSpan.FromSeconds(Math.Min(30, Math.Pow(2, retries) * 2));
            var retryAt = DateTimeOffset.UtcNow.Add(delay);
            var retryResult = AgentUpdateInstallerResult.FromMsiExitCode(
                exitCode,
                "Windows Installer is busy; retry scheduled.",
                null) with
            {
                AttemptId = plan.AttemptId,
                RetryCount = retries,
                RetryAfterUtc = retryAt.ToString("O"),
            };
            WriteInstallerResult(retryResult, log);
            Thread.Sleep(delay);
        }
    }

    private static int ReadDurableRetryCount(AgentUpdatePlan plan, UpdaterLog log)
    {
        try
        {
            var result = AgentUpdateStateStore.CreateDefault()
                .ReadInstallerResultAsync(CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            return result is not null &&
                   string.Equals(result.AttemptId, plan.AttemptId, StringComparison.Ordinal) &&
                   string.Equals(result.ErrorCode, AgentUpdateErrorCodes.InstallerBusy, StringComparison.Ordinal)
                ? Math.Max(0, result.RetryCount)
                : 0;
        }
        catch (Exception ex)
        {
            log.Write($"Durable installer retry state could not be read: {ex.GetType().Name}.");
            return 0;
        }
    }

    private static DateTimeOffset ReadDurableRetryAfter(AgentUpdatePlan plan, UpdaterLog log)
    {
        try
        {
            var result = AgentUpdateStateStore.CreateDefault()
                .ReadInstallerResultAsync(CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            return result is not null &&
                   string.Equals(result.AttemptId, plan.AttemptId, StringComparison.Ordinal) &&
                   string.Equals(result.ErrorCode, AgentUpdateErrorCodes.InstallerBusy, StringComparison.Ordinal) &&
                   DateTimeOffset.TryParse(result.RetryAfterUtc, out var retryAfter)
                ? retryAfter.ToUniversalTime()
                : DateTimeOffset.MinValue;
        }
        catch (Exception ex)
        {
            log.Write($"Durable installer retry schedule could not be read: {ex.GetType().Name}.");
            return DateTimeOffset.MinValue;
        }
    }

    private static int RunMsiexec(AgentUpdatePlan plan, string msiLogPath, UpdaterLog log)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "msiexec.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("/i");
        psi.ArgumentList.Add(plan.ArtifactPath);
        psi.ArgumentList.Add("/qn");
        psi.ArgumentList.Add("/norestart");
        psi.ArgumentList.Add("CERBERUS_EULA_ACCEPTED=1");
        psi.ArgumentList.Add("/l*v");
        psi.ArgumentList.Add(msiLogPath);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("Windows Installer could not be started.");
        log.Write("Windows Installer started.");
        process.WaitForExit();
        _ = process.StandardOutput.ReadToEnd();
        _ = process.StandardError.ReadToEnd();
        log.Write($"msiexec exit code: {process.ExitCode}.");
        return process.ExitCode;
    }

    private static void WriteInstallerResult(AgentUpdateInstallerResult result, UpdaterLog log)
    {
        try
        {
            AgentUpdateStateStore.CreateDefault()
                .WriteInstallerResultAsync(result with { MsiLogPath = null }, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
            log.Write($"Updater result written: state={result.State}; code={result.ErrorCode ?? "-"}; msi_exit={result.MsiExitCode?.ToString() ?? "-"}.");
        }
        catch (Exception ex)
        {
            log.Write($"Updater result write failed: {ex.GetType().Name}.");
        }
    }

    private static void WriteCurrentStateFromPlan(AgentUpdatePlan plan, AgentUpdateInstallerResult result, UpdaterLog log)
    {
        try
        {
            AgentUpdateStateStore.CreateDefault()
                .WriteTransitionAsync(
                    AgentUpdateStates.Current,
                    plan.Version,
                    CancellationToken.None,
                    targetVersion: plan.Version,
                    channel: plan.Channel,
                    artifactSha256: plan.Sha256,
                    msiExitCode: result.MsiExitCode,
                    requiresReboot: result.RequiresReboot,
                    markChecked: true,
                    installerResultId: result.ResultId,
                    attemptId: plan.AttemptId,
                    sequence: plan.Sequence,
                    retryCount: result.RetryCount).GetAwaiter().GetResult();
            log.Write("Updater current state written.");
        }
        catch (Exception ex)
        {
            log.Write($"Updater current state write failed: {ex.GetType().Name}.");
        }
    }

    private static void StopServiceChecked()
    {
        try
        {
            ServiceInstaller.StopOrThrow();
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("not installed", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Installed service is required for update authority.", ex);
        }
    }

    private static void StartServiceChecked()
        => ServiceInstaller.StartOrThrow();

    private static void TryStartService(UpdaterLog log)
    {
        try
        {
            StartServiceChecked();
        }
        catch (Exception ex)
        {
            log.Write($"Service restart failed: {ex.GetType().Name}.");
        }
    }

    private static void ValidateCanonicalServiceLayout()
    {
        var runtimeRoot = ResolveRuntimeRoot();
        var servicePath = Path.Combine(runtimeRoot, "Cerberus.Agent.Service.exe");
        AgentUpdateSecurity.ValidateTrustedPath(runtimeRoot, Path.GetPathRoot(runtimeRoot) ?? runtimeRoot, allowMissing: false);
        AgentUpdateSecurity.ValidateTrustedPath(servicePath, runtimeRoot, allowMissing: false);
        if (!File.Exists(servicePath))
            throw new InvalidOperationException("Canonical service executable is missing.");

        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceInstaller.ServiceName}", writable: false);
        var imagePath = key?.GetValue("ImagePath")?.ToString();
        var installedPath = ServiceInstaller.ExtractExecutablePathFromServiceImagePath(imagePath);
        if (!ServiceInstaller.ServiceExecutableMatches(installedPath, servicePath))
            throw new InvalidOperationException("Installed service path does not match the canonical layout.");
    }

    private static string ResolveRuntimeRoot()
    {
        var runtimeRoot = ReadRegistryString(@"Software\Cerberus\WindowsAgent", "runtimeRoot");
        var installRoot = ReadRegistryString(@"Software\Cerberus\WindowsAgent", "installRoot");
        if (string.IsNullOrWhiteSpace(runtimeRoot) && string.IsNullOrWhiteSpace(installRoot))
            throw new InvalidOperationException("Canonical agent runtime root is not registered.");

        var resolvedRuntimeRoot = !string.IsNullOrWhiteSpace(runtimeRoot)
            ? Path.GetFullPath(runtimeRoot.Trim())
            : Path.Combine(Path.GetFullPath(installRoot!.Trim()), "app");
        if (!string.IsNullOrWhiteSpace(runtimeRoot) && !string.IsNullOrWhiteSpace(installRoot))
        {
            var expectedRuntimeRoot = Path.Combine(Path.GetFullPath(installRoot.Trim()), "app");
            if (!string.Equals(resolvedRuntimeRoot, expectedRuntimeRoot, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Registered agent runtime layout is inconsistent.");
        }

        AgentUpdateSecurity.ValidateTrustedPath(
            resolvedRuntimeRoot,
            Path.GetPathRoot(resolvedRuntimeRoot) ?? resolvedRuntimeRoot,
            allowMissing: false);
        return resolvedRuntimeRoot;
    }

    private static void WaitForLocalHealthGate(TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow.Add(timeout);
        using var controller = new System.ServiceProcess.ServiceController(ServiceInstaller.ServiceName);
        while (DateTimeOffset.UtcNow < deadline)
        {
            controller.Refresh();
            if (controller.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                return;
            Thread.Sleep(250);
        }

        throw new InvalidOperationException("Agent service local health gate failed.");
    }

    private static void QuarantineAttempt(AgentUpdatePlan plan, UpdaterLog log)
    {
        try
        {
            var root = AgentUpdateStager.DefaultStagingRoot;
            var attempt = AgentUpdateSecurity.ResolveAttemptDirectory(root, plan.AttemptId ?? "");
            var quarantine = Path.Combine(Path.GetDirectoryName(attempt) ?? root, "quarantine-" + plan.AttemptId);
            Directory.Move(attempt, quarantine);
            log.Write("Update attempt quarantined.");
        }
        catch (Exception ex)
        {
            log.Write($"Update attempt quarantine failed: {ex.GetType().Name}.");
        }
    }

    private static ClosedApplications CloseAgentUiApplications()
    {
        var uiSessions = new HashSet<int>();
        var uiWasRunning = false;
        foreach (var name in new[] { "Cerberus.Agent", "Cerberus.Agent.Tray", "Cerberus.Agent.Setup", "Cerberus.Agent.App" })
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                try
                {
                    if (name is "Cerberus.Agent" or "Cerberus.Agent.Tray" or "Cerberus.Agent.Setup")
                    {
                        uiWasRunning = true;
                        if (process.SessionId > 0)
                            uiSessions.Add(process.SessionId);
                    }

                    if (!process.CloseMainWindow())
                        process.Kill(entireProcessTree: true);
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                }
                finally
                {
                    process.Dispose();
                }
            }
        }

        return new ClosedApplications(uiWasRunning, uiSessions.ToArray());
    }

    private static void TryRestartAgentUi(ClosedApplications closedApplications, UpdaterLog log)
    {
        if (!closedApplications.UiWasRunning)
            return;

        string runtimeRoot;
        try
        {
            runtimeRoot = ResolveRuntimeRoot();
        }
        catch (Exception ex)
        {
            log.Write($"Agent UI restart skipped: {ex.GetType().Name}.");
            return;
        }

        var agentUiPath = Path.Combine(runtimeRoot, "Cerberus.Agent.exe");
        try
        {
            AgentUpdateSecurity.ValidateTrustedPath(agentUiPath, runtimeRoot, allowMissing: false);
        }
        catch (Exception ex)
        {
            log.Write($"Agent UI restart skipped: {ex.GetType().Name}.");
            return;
        }
        if (!File.Exists(agentUiPath))
            return;
        var sessionIds = closedApplications.UiSessionIds.Count > 0
            ? closedApplications.UiSessionIds
            : ActiveSessionProcessLauncher.GetActiveConsoleSessionIds();
        var started = 0;
        foreach (var sessionId in sessionIds.Distinct().Where(id => id > 0))
        {
            if (ActiveSessionProcessLauncher.TryLaunch(agentUiPath, sessionId, log))
                started++;
        }
        log.Write($"Agent UI restart requested for {started} session(s).");
    }

    private static string? ReadRegistryString(string subKey, string valueName)
    {
        using var key = Registry.LocalMachine.OpenSubKey(subKey, writable: false);
        return key?.GetValue(valueName)?.ToString();
    }

    private sealed class UpdaterLog
    {
        private readonly string _path;

        private UpdaterLog(string path) => _path = path;

        public static UpdaterLog Create()
        {
            var root = Path.Combine(AgentUpdateStager.DefaultStagingRoot, "logs");
            AgentUpdateSecurity.EnsureProtectedRoot(AgentUpdateStager.DefaultStagingRoot);
            Directory.CreateDirectory(root);
            return new UpdaterLog(Path.Combine(root, $"updater-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Environment.ProcessId}.log"));
        }

        public string CreateSiblingLogPath(string prefix)
            => Path.Combine(Path.GetDirectoryName(_path) ?? AgentUpdateStager.DefaultStagingRoot, $"{prefix}-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Environment.ProcessId}.log");

        public void Write(string message)
        {
            try
            {
                File.AppendAllText(_path, $"[{DateTimeOffset.UtcNow:O}] {AgentUpdateState.SanitizeMessage(message)}{Environment.NewLine}");
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private sealed record ClosedApplications(bool UiWasRunning, IReadOnlyCollection<int> UiSessionIds);

    private static class ActiveSessionProcessLauncher
    {
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint InvalidSessionId = 0xFFFFFFFF;

        public static IReadOnlyCollection<int> GetActiveConsoleSessionIds()
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            return sessionId == InvalidSessionId || sessionId == 0 ? Array.Empty<int>() : new[] { checked((int)sessionId) };
        }

        public static bool TryLaunch(string agentUiPath, int sessionId, UpdaterLog log)
        {
            if (sessionId <= 0)
                return false;
            IntPtr token = IntPtr.Zero;
            IntPtr environment = IntPtr.Zero;
            PROCESS_INFORMATION processInfo = default;
            try
            {
                if (!WTSQueryUserToken((uint)sessionId, out token) || !CreateEnvironmentBlock(out environment, token, false))
                    return false;
                var startupInfo = new STARTUPINFO
                {
                    cb = System.Runtime.InteropServices.Marshal.SizeOf<STARTUPINFO>(),
                    lpDesktop = @"winsta0\default",
                    dwFlags = 1,
                    wShowWindow = 1,
                };
                var commandLine = new System.Text.StringBuilder($"\"{agentUiPath}\"");
                if (!CreateProcessAsUser(token, null, commandLine, IntPtr.Zero, IntPtr.Zero, false, CreateUnicodeEnvironment, environment, Path.GetDirectoryName(agentUiPath), ref startupInfo, out processInfo))
                    return false;
                return true;
            }
            catch (Exception ex)
            {
                log.Write($"Agent UI restart failed: {ex.GetType().Name}.");
                return false;
            }
            finally
            {
                if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
                if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
                if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();
        [System.Runtime.InteropServices.DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
        [System.Runtime.InteropServices.DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
        [System.Runtime.InteropServices.DllImport("userenv.dll", SetLastError = true)]
        private static extern bool DestroyEnvironmentBlock(IntPtr environment);
        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern bool CreateProcessAsUser(IntPtr token, string? applicationName, System.Text.StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
    }
}
