using System.Diagnostics;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Microsoft.Win32;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Updater;

internal static class Program
{
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

        AgentUpdatePlan? plan = null;
        var root = AgentUpdateStager.DefaultStagingRoot;
        var journalStore = new AgentUpdateJournalStore(root);
        var ownsAttempt = false;
        try
        {
            var attemptDirectory = AgentUpdateSecurity.ResolveAttemptDirectory(root, attemptId);
            using var executionLock = new FileStream(Path.Combine(attemptDirectory, "execution.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var active = journalStore.Read();
            if (active.AttemptId != attemptId || active.Phase != "launch_requested")
                throw new InvalidOperationException("Update attempt is not authorized for installation.");
            ownsAttempt = true;
            var runnerDirectory = Path.Combine(attemptDirectory, AgentUpdateRunnerFiles.RunnerDirectoryName);
            if (!string.Equals(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar), runnerDirectory, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Updater must execute from the protected attempt copy.");
            AgentUpdateRunnerFiles.Validate(runnerDirectory, attemptDirectory);
            plan = LoadAndValidateAttempt(attemptId, attemptDirectory, log);
            var trust = AgentUpdateTrustFactory.BuildTrust();
            var manifest = LoadAndValidateManifest(plan, attemptDirectory, trust);
            ValidateAttemptArtifact(plan, manifest, attemptDirectory, root, trust);
            ValidateCanonicalServiceLayout();

            var msiLogPath = log.CreateSiblingLogPath("msiexec");
            // Never tie the installer lifetime to the service or a cancellation token.
            // A crash after the flushed launch fence requires reconciliation, not another launch.
            var exitCode = RunMsiexec(plan, msiLogPath, log);
            var installerResult = AgentUpdateInstallerResult.FromMsiExitCode(
                exitCode,
                exitCode == 0 || exitCode == 3010 ? null : "msiexec failed.",
                msiLogPath) with
            {
                AttemptId = plan.AttemptId,
                RetryCount = active.RetryCount,
            };
            journalStore.ChangeAttempt(attemptId, before => before with
            {
                Phase = installerResult.State,
                InstallerResult = installerResult,
            });
            WriteInstallerResult(installerResult, log);
            log.Write("Cerberus Agent updater completed.");
            return exitCode;
        }
        catch (Exception ex)
        {
            log.Write($"Updater failed: {ex.GetType().Name}.");
            var result = AgentUpdateInstallerResult.Failure(new InvalidOperationException("Updater requires recovery.")) with
            {
                AttemptId = plan?.AttemptId ?? attemptId,
            };
            try
            {
                if (ownsAttempt) journalStore.ChangeAttempt(attemptId, before => before.Phase is AgentUpdateStates.Blocked or AgentUpdateStates.Installed or AgentUpdateStates.Failed or AgentUpdateStates.Quarantined
                    ? before : before with
                {
                    Phase = before.MayHaveStartedInstallation ? AgentUpdateStates.RecoveryRequired : AgentUpdateStates.Failed,
                    InstallerResult = before.InstallerResult ?? result,
                });
            }
            catch (Exception failure) { log.Write($"Updater result persistence failed: {failure.GetType().Name}."); }
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
        var plan = AgentUpdateDurableFile.Read<AgentUpdatePlan>(planPath, attemptDirectory)
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
        if (new FileInfo(manifestPath).Length > AgentUpdateDurableFile.MaxBytes)
            throw new InvalidOperationException("Update manifest exceeds size limit.");
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
        var digest = AgentUpdateManifestValidator.Digest(manifest);
        if (plan.ManifestDigest != digest)
            throw new InvalidOperationException("Update plan manifest digest mismatch.");
        AgentUpdateSequenceStore.RequireAccepted(AgentUpdateStager.DefaultStagingRoot, manifest.Sequence, digest);
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

        if (!expected.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Contains(actual, StringComparer.OrdinalIgnoreCase))
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

        AgentUpdateAuthenticode.Verify(
            artifactPath,
            trust.ExpectedChannel,
            trust.AllowedSignerKeyIdentity,
            trust.AllowUnsignedDevBuild);
    }

    private static int RunMsiexec(AgentUpdatePlan plan, string msiLogPath, UpdaterLog log)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "msiexec.exe"),
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

        Process process;
        using (AgentUpdateLaunchFence.AcquireAsync(CancellationToken.None).GetAwaiter().GetResult())
        {
            var journalStore = new AgentUpdateJournalStore(AgentUpdateStager.DefaultStagingRoot);
            var active = journalStore.Read();
            var lifecycle = new DurableAgentLifecycleStateStore().LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
            if (active.AttemptId != plan.AttemptId || active.Phase != "launch_requested" ||
                lifecycle.Generation != active.LifecycleGeneration ||
                (active.Automatic && (!lifecycle.QuiescenceComplete || !AgentLifecycleStates.AllowsAutomaticNetwork(lifecycle.State))))
                throw new InvalidOperationException("Update attempt authorization changed.");
            journalStore.ChangeAttempt(plan.AttemptId!, before => before with
            {
                Phase = "install_may_have_started", InstallationBootId = AgentUpdateBootIdentity.Read(),
            });
            process = Process.Start(psi) ?? throw new InvalidOperationException("Windows Installer could not be started.");
            journalStore.ChangeAttempt(plan.AttemptId!, before => before with
            {
                Phase = AgentUpdateStates.Installing,
                InstallerProcessId = process.Id,
                InstallerStartedUtc = new DateTimeOffset(process.StartTime.ToUniversalTime()),
            });
        }
        using var ownedProcess = process;
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
        var resolvedRuntimeRoot = AgentUpdateSecurity.ResolveRegisteredRuntimeRoot(runtimeRoot, installRoot);

        AgentUpdateSecurity.ValidateTrustedPath(
            resolvedRuntimeRoot,
            Path.GetPathRoot(resolvedRuntimeRoot) ?? resolvedRuntimeRoot,
            allowMissing: false);
        return resolvedRuntimeRoot;
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


}
