using System.IO;
using System.Net.Http;
using System.Text.RegularExpressions;
using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App;

/// <summary>Production host: SCM, control pipe, DPAPI stores and the protected provisioning directory.</summary>
internal sealed class WindowsHeadlessHost : IHeadlessHost
{
    private static readonly Regex FingerprintLine = new(
        "^Agent key fingerprint=sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AgentInstallIdentity.DataDirName);
    private static string FingerprintPath => Path.Combine(DataDirectory, EnrollHeadlessMode.FingerprintFileName);

    public bool IsAdministrator => Elevation.IsAdministrator();
    public bool IsLocalSystem => AgentUpdateSecurity.IsLocalSystem();

    public HeadlessServiceState GetServiceState() => AgentStatus.GetService() switch
    {
        { Installed: false } => HeadlessServiceState.NotInstalled,
        { Text: "stopped" } => HeadlessServiceState.Stopped,
        { Text: "starting" } => HeadlessServiceState.Starting,
        { Text: "running" } => HeadlessServiceState.Running,
        _ => HeadlessServiceState.Other,
    };

    public async Task<HeadlessServiceState> EnsureRunningAsync(bool startIfStopped, CancellationToken ct)
    {
        var state = GetServiceState();
        if (state == HeadlessServiceState.Stopped && startIfStopped)
        {
            try { await Task.Run(ServiceInstaller.StartOrThrow, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or System.ServiceProcess.TimeoutException)
            {
                return GetServiceState();
            }
        }
        for (var i = 0; i < 60 && (state = GetServiceState()) == HeadlessServiceState.Starting; i++)
            await Task.Delay(500, ct).ConfigureAwait(false);
        return state;
    }

    public string? ResolveBackendUrl()
        => BootstrapResolver.ResolveConfiguredBackend(UiConfigStore.LoadMergedWithEnv())?.BackendUrl;

    public HeadlessEnrollmentOptions BuildOptions(string backendUrl) => new(
        backendUrl,
        WindowsDeviceInfo.ComputeDeviceFingerprint(),
        WindowsDeviceInfo.GetAgentVersion(),
        WindowsDeviceInfo.GetBuildId(),
        WindowsDeviceInfo.GetBuildChannel(),
        Environment.MachineName);

    public bool HasMachineCredentials() => File.Exists(DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.Machine));

    public Task<AgentLifecycleSnapshot> LoadLifecycleAsync(CancellationToken ct)
        => new DurableAgentLifecycleStateStore().LoadAsync(ct);

    public ISecretStore OpenDestination(bool userScope)
        => userScope ? new DpapiSecretStore(SecretStoreScope.User) : new PendingCredentialStore();

    // A redirect would replay the proof to another host.
    public HttpClient CreateHttpClient(Uri backend)
        => new(new HttpClientHandler { AllowAutoRedirect = false }) { BaseAddress = backend, Timeout = TimeSpan.FromSeconds(30) };

    public async Task<string?> ActivateAsync(bool commitDirectly, CancellationToken ct)
    {
        if (commitDirectly)
            return await CommitDirectlyAsync(ct).ConfigureAwait(false);

        string? code = null;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            // The marker binds the lifecycle generation, which can move while the service finishes starting.
            using (await AgentUpdateLaunchFence.AcquireForEnrollmentPromotionAsync(ct).ConfigureAwait(false))
            {
                var lifecycle = await new DurableAgentLifecycleStateStore().LoadAsync(ct).ConfigureAwait(false);
                AgentCredentialPublication.RequireNoUnresolvedPublication();
                await AgentEnrollmentPromotion.WriteAsync(lifecycle.Generation, AgentEnrollmentPromotion.OpenPendingStore(), ct)
                    .ConfigureAwait(false);
            }
            var response = await AgentLocalControlClient.SendAsync(new("enrollment-adopt"), ct).ConfigureAwait(false);
            if (response.Success)
                return null;
            code = response.Code;
            if (code is not ("enrollment_proof_required" or "enrollment_proof_stale" or "recovery_busy" or "enrollment_validation_unavailable"))
                break;
            await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
        }
        return code ?? "adopt_failed";
    }

    // LocalSystem with the service stopped: the same checks and commit the service runs for enrollment-adopt.
    private static async Task<string?> CommitDirectlyAsync(CancellationToken ct)
    {
        using var fence = await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false);
        var durable = new DurableAgentLifecycleStateStore();
        var current = await durable.LoadAsync(ct).ConfigureAwait(false);
        if (!current.QuiescenceComplete || current.ReasonCode == AgentLifecycleStatePolicy.AgentRevokedCode)
            return "state_refused";
        AgentCredentialPublication.RequireNoUnresolvedPublication();
        var pending = AgentEnrollmentPromotion.OpenPendingStore();
        await AgentEnrollmentPromotion.WriteAsync(current.Generation, pending, ct).ConfigureAwait(false);
        var marker = await AgentEnrollmentPromotion.ReadAsync(ct).ConfigureAwait(false);
        if (marker is null || !await AgentEnrollmentPromotion.MatchesAsync(marker, pending, ct).ConfigureAwait(false))
            return "enrollment_identity_mismatch";
        await durable.CommitEnrollmentAsync(current.Generation, marker.Nonce,
            cancel => AgentCredentialPublication.BeginAsync(durable, current.Generation, marker.Nonce, cancel), ct).ConfigureAwait(false);
        return null;
    }

    public string? ReadFingerprintLine()
    {
        try
        {
            var first = ProtectedFingerprintFile.ReadFirstLine(FingerprintPath)?.Trim();
            return first is not null && FingerprintLine.IsMatch(first) ? first : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void WriteFingerprintFile(string content)
    {
        Directory.CreateDirectory(DataDirectory);
        var temporary = FingerprintPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            ProtectedFingerprintFile.Write(temporary, content);
            File.Move(temporary, FingerprintPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    public Task WriteTenantContextAsync(AgentIdentity identity, string? tenantName, CancellationToken ct)
        => AgentUiContextStore.WriteBestEffortAsync(identity, tenantName, accountLabel: null, ct);

    public IAgentLogger OpenLog()
    {
        try { return AgentFileLogger.CreateService(alsoConsole: false); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return NullAgentLogger.Instance;
        }
    }

#if CERBERUS_SERVER_PROFILE
    public bool EnsureDataRootProtected() => ServerDataRoot.EnsureProtected();

    public IDisposable? TryAcquireEnrollLock(TimeSpan wait) => EnrollLock.TryAcquire(wait, out var held) switch
    {
        EnrollLockOutcome.Acquired => held,
        EnrollLockOutcome.Busy => null,
        _ => throw new UnauthorizedAccessException("Enroll lock is not trusted."),
    };

    public Task DiscardPendingEnrollmentAsync(CancellationToken ct) => ServerEnrollmentArtifacts.DiscardPendingAsync(ct);

    public Task<bool> DiscardStalePendingEnrollmentAsync(CancellationToken ct) => ServerEnrollmentArtifacts.DiscardStalePendingAsync(ct);
#else
    public void InstallDesktopService() => AgentServiceProvisioning.InstallOrThrow();
#endif

    /// <summary>Stages credentials in the protected pending directory; the service (or the installer) commits them.</summary>
    private sealed class PendingCredentialStore : ISecretStore
    {
        public async Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
        {
            using var fence = await AgentUpdateLaunchFence.AcquireForEnrollmentPromotionAsync(ct).ConfigureAwait(false);
            AgentCredentialPublication.RequireNoUnresolvedPublication();
            await AgentEnrollmentPromotion.OpenPendingStore()
                .SaveAsync(identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey, ct)
                .ConfigureAwait(false);
        }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => AgentEnrollmentPromotion.OpenPendingStore().LoadAsync(ct);

        public Task ClearAsync(CancellationToken ct) => throw new InvalidOperationException("Pending enrollment cannot be cleared here.");
    }
}
