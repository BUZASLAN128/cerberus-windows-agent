using Cerberus.Agent.Core;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Security;
using Cerberus.Agent.App.Control;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.App.Actions;

internal sealed record AgentServiceCredentialPromotionResult(string AgentId, string TenantId);

internal static class AgentServiceCredentialBridge
{
    public static Task<AgentServiceCredentialPromotionResult> SyncMachineSecretsToUserAsync(CancellationToken ct)
        => PromoteAsync(
            new DpapiSecretStore(SecretStoreScope.Machine),
            new DpapiSecretStore(SecretStoreScope.User),
            ct);

    internal static async Task<AgentServiceCredentialPromotionResult> PromoteAsync(
        ISecretStore userStore,
        ISecretStore machineStore,
        CancellationToken ct)
    {
        var (identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey) =
            await userStore.LoadAsync(ct).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(identity.AgentId) ||
            string.IsNullOrWhiteSpace(identity.TenantId) ||
            string.IsNullOrWhiteSpace(refreshToken) ||
            string.IsNullOrWhiteSpace(privateKeyPem) ||
            string.IsNullOrWhiteSpace(backendUrl))
        {
            throw new InvalidOperationException("User-scope agent registration is incomplete.");
        }

        AgentEnrollmentProbeStore? previous = null;
        try { previous = new AgentEnrollmentProbeStore(await machineStore.LoadAsync(ct).ConfigureAwait(false)); }
        catch (FileNotFoundException) { }
        catch (DirectoryNotFoundException) { }
        try
        {
            await machineStore
                .SaveAsync(identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey, ct)
                .ConfigureAwait(false);

        var (verifiedIdentity, verifiedRefreshToken, verifiedPrivateKeyPem, verifiedBackendUrl, verifiedTailscaleLoginServer, verifiedTailscaleAuthkey) =
            await machineStore.LoadAsync(ct).ConfigureAwait(false);

        if (!string.Equals(verifiedIdentity.AgentId, identity.AgentId, StringComparison.Ordinal) ||
            !string.Equals(verifiedIdentity.TenantId, identity.TenantId, StringComparison.Ordinal) ||
            !string.Equals(verifiedBackendUrl, backendUrl, StringComparison.Ordinal) ||
            !string.Equals(verifiedRefreshToken, refreshToken, StringComparison.Ordinal) ||
            !string.Equals(verifiedPrivateKeyPem, privateKeyPem, StringComparison.Ordinal) ||
            !string.Equals(verifiedTailscaleLoginServer, tailscaleLoginServer, StringComparison.Ordinal) ||
            !string.Equals(verifiedTailscaleAuthkey, tailscaleAuthkey, StringComparison.Ordinal) ||
            !string.Equals(
                CredentialFingerprint(identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey),
                CredentialFingerprint(verifiedIdentity, verifiedRefreshToken, verifiedPrivateKeyPem, verifiedBackendUrl, verifiedTailscaleLoginServer, verifiedTailscaleAuthkey),
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Machine-scope agent registration verification failed.");
        }

            return new AgentServiceCredentialPromotionResult(identity.AgentId, identity.TenantId);
        }
        catch
        {
            if (previous is not null)
            {
                using var rollback = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await previous.PublishAsync(machineStore, rollback.Token).ConfigureAwait(false);
            }
            throw;
        }
    }

    private static string CredentialFingerprint(
        AgentIdentity identity,
        string refreshToken,
        string privateKeyPem,
        string backendUrl,
        string? tailscaleLoginServer,
        string? tailscaleAuthkey)
    {
        var canonical = string.Join(
            "\u001f",
            identity.AgentId,
            identity.TenantId,
            refreshToken,
            privateKeyPem,
            backendUrl,
            tailscaleLoginServer ?? "",
            tailscaleAuthkey ?? "");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    internal static async Task<AgentServiceCredentialPromotionResult> PromoteAndClearSourceAsync(
        ISecretStore userStore,
        ISecretStore machineStore,
        CancellationToken ct)
    {
        var result = await PromoteAsync(userStore, machineStore, ct).ConfigureAwait(false);
        await userStore.ClearAsync(ct).ConfigureAwait(false);
        return result;
    }
}

internal static class AgentServiceLocalState
{
    public static async Task ClearMachineStateAsync(CancellationToken ct)
    {
        // The elevated removal caller runs after SCM has stopped the agent. Keep
        // this guard local as well so a failed stop cannot race a service-created
        // BITS job while the protected update tree is being removed.
        Cerberus.Agent.App.ServiceInstaller.RequireStoppedOrAbsent();

        // Admin removal cannot use the service's caller-owned EnumJobs(0)
        // inventory. The all-users path remains narrowly scoped to SYSTEM jobs
        // whose protected attempt marker, receipt and destination all bind them
        // to this update root; any ambiguity fails before state deletion.
        AgentUpdateBitsDownloader.QuiesceForRemoval(AgentUpdateSecurity.DefaultPrivilegedRoot);
        await new DpapiSecretStore(SecretStoreScope.Machine).ClearAsync(ct).ConfigureAwait(false);

        var baseDir = DpapiSecretStore.GetDefaultBaseDir(SecretStoreScope.Machine);
        DeleteFileIfExists(Path.Combine(baseDir, "idempotency.json"));
        DeleteFileIfExists(Path.Combine(baseDir, "telemetry-offline.json"));
        DeleteDirectoryIfExists(Path.Combine(baseDir, "updates"));
        DeleteDirectoryIfExists(AgentUpdateSecurity.DefaultPrivilegedRoot);
    }

    private static void DeleteFileIfExists(string path)
    {
        if (File.Exists(path))
            File.Delete(path);
    }

    private static void DeleteDirectoryIfExists(string path)
    {
        if (Directory.Exists(path))
            Directory.Delete(path, recursive: true);
    }
}

internal static class AgentBackendLifecycle
{
    public const string UnregisterReasonCode = "agent_unregister_device";
    public const string UnregisterReason = "Device unregistered from Windows agent";

    public static async Task<bool> TrySelfDeactivateAsync(
        ISecretStore store,
        string reasonCode,
        string reason,
        CancellationToken ct)
    {
        try
        {
            var (_, _, privateKeyPem, backendUrl, _, _) = await store.LoadAsync(ct).ConfigureAwait(false);
            using var http = new HttpClient
            {
                BaseAddress = new Uri(backendUrl.TrimEnd('/')),
                Timeout = TimeSpan.FromSeconds(20),
            };
            var api = new AgentApiClient(
                http,
                store,
                new AgentTokenManager(http, store),
                new RequestSigner(privateKeyPem));
            await api.SelfDeactivateAsync(
                new AgentSelfDeactivateRequest(
                    SchemaVersion: "agent.self-deactivate.v1",
                    ReasonCode: reasonCode,
                    Reason: reason),
                ct).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }
}

internal static class AgentServiceProvisioning
{
    internal sealed record InstallRegistrationState(bool StagedFromUserScope);

    internal static async Task<bool> PreserveMachineRegistrationForUserAsync(
        ISecretStore machineStore,
        ISecretStore userStore,
        bool machineRegistrationExpected,
        CancellationToken ct)
    {
        if (!machineRegistrationExpected)
            return false;

        await AgentServiceCredentialBridge.PromoteAsync(machineStore, userStore, ct).ConfigureAwait(false);
        return true;
    }

    internal static async Task<InstallRegistrationState> PrepareRegistrationForInstallAsync(
        ISecretStore userStore,
        ISecretStore machineStore,
        ISecretStore pendingStore,
        CancellationToken ct,
        AgentLifecycleSnapshot? lifecycle = null)
    {
        if (lifecycle is not null &&
            (!lifecycle.QuiescenceComplete || lifecycle.ReasonCode == AgentLifecycleStatePolicy.AgentRevokedCode))
            throw new InvalidOperationException("Service lifecycle does not allow enrollment promotion.");
        if (lifecycle is not null && AgentLifecycleStates.AllowsAutomaticNetwork(lifecycle.State) &&
            await HasCompleteRegistrationAsync(machineStore, ct).ConfigureAwait(false))
        {
            if (await HasCompleteRegistrationAsync(userStore, ct).ConfigureAwait(false))
            {
                var user = await userStore.LoadAsync(ct).ConfigureAwait(false);
                var machine = await machineStore.LoadAsync(ct).ConfigureAwait(false);
                if (user.Identity != machine.Identity || user.PrivateKeyPem != machine.PrivateKeyPem)
                    throw new InvalidOperationException("An active machine registration cannot be replaced by service setup.");
            }
            return new InstallRegistrationState(StagedFromUserScope: false);
        }
        if (await HasCompleteRegistrationAsync(userStore, ct).ConfigureAwait(false))
        {
            // Never write the authoritative store during elevated setup. Keep a
            // rotated pending token on retry when it belongs to the same proof.
            var user = await userStore.LoadAsync(ct).ConfigureAwait(false);
            var reusePending = false;
            if (await HasCompleteRegistrationAsync(pendingStore, ct).ConfigureAwait(false))
            {
                var pending = await pendingStore.LoadAsync(ct).ConfigureAwait(false);
                reusePending = pending.Identity == user.Identity && pending.PrivateKeyPem == user.PrivateKeyPem && pending.BackendUrl == user.BackendUrl;
            }
            if (!reusePending)
                await AgentServiceCredentialBridge.PromoteAsync(userStore, pendingStore, ct).ConfigureAwait(false);
            return new InstallRegistrationState(StagedFromUserScope: true);
        }

        if (await HasCompleteRegistrationAsync(machineStore, ct).ConfigureAwait(false))
            return new InstallRegistrationState(StagedFromUserScope: false);

        throw new InvalidOperationException("No complete agent registration was found. Sign in and register the agent before installing the service.");
    }

    private static async Task<bool> HasCompleteRegistrationAsync(ISecretStore store, CancellationToken ct)
    {
        try
        {
            var (identity, refreshToken, privateKeyPem, backendUrl, _, _) =
                await store.LoadAsync(ct).ConfigureAwait(false);

            return !string.IsNullOrWhiteSpace(identity.AgentId) &&
                   !string.IsNullOrWhiteSpace(identity.TenantId) &&
                   !string.IsNullOrWhiteSpace(refreshToken) &&
                   !string.IsNullOrWhiteSpace(privateKeyPem) &&
                   !string.IsNullOrWhiteSpace(backendUrl);
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (DirectoryNotFoundException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return false;
        }
    }

    internal static async Task<bool> DeactivateAndClearRegistrationAsync(
        ISecretStore store,
        Func<ISecretStore, string, string, CancellationToken, Task<bool>> selfDeactivate,
        CancellationToken ct)
    {
        if (!await HasCompleteRegistrationAsync(store, ct).ConfigureAwait(false))
            return false;

        var deactivated = await selfDeactivate(
            store,
            AgentBackendLifecycle.UnregisterReasonCode,
            AgentBackendLifecycle.UnregisterReason,
            ct).ConfigureAwait(false);
        if (!deactivated)
        {
            throw new InvalidOperationException(
                "Could not unregister this device from the Cerberus portal. Local registration was kept so portal and device state do not drift.");
        }

        await store.ClearAsync(ct).ConfigureAwait(false);
        return true;
    }

    public static void InstallOrThrow()
    {
        if (!Elevation.IsAdministrator())
            throw new InvalidOperationException("Administrator privileges are required for service install/uninstall.");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(120));
        var userStore = new DpapiSecretStore(SecretStoreScope.User);
        var machineStore = new DpapiSecretStore(SecretStoreScope.Machine);

        AgentLegalConsent.RequireCurrentInstallConsent();
        var userRegistrationAvailable = HasCompleteRegistrationAsync(userStore, cts.Token)
            .GetAwaiter()
            .GetResult();
        InstallRegistrationState registrationState;
        using (AgentUpdateLaunchFence.AcquireForEnrollmentPromotionAsync(cts.Token).GetAwaiter().GetResult())
        {
            var lifecycle = new DurableAgentLifecycleStateStore().LoadAsync(cts.Token).GetAwaiter().GetResult();
            AgentCredentialPublication.RequireNoUnresolvedPublication();
            var pendingStore = AgentEnrollmentPromotion.OpenPendingStore();
            registrationState = PrepareRegistrationForInstallAsync(userStore, machineStore, pendingStore, cts.Token, lifecycle)
                .GetAwaiter().GetResult();
            if (registrationState.StagedFromUserScope)
                AgentEnrollmentPromotion.WriteAsync(lifecycle.Generation, pendingStore, cts.Token).GetAwaiter().GetResult();
        }
        try
        {
            if (!userRegistrationAvailable)
                AgentClaimGate.RequireClaimedForServiceInstall(machineStore, cts.Token);
            AgentLegalConsent.EnsureMachineConsentForInstall();
            InstallPreparedRegistrationAsync(registrationState, userStore, userRegistrationAvailable,
                () => { ServiceInstaller.InstallOrThrow(); return Task.CompletedTask; },
                cancel => AgentLocalControlClient.SendAsync(new("enrollment-adopt"), cancel), cts.Token).GetAwaiter().GetResult();
        }
        catch
        {
            // SCM/probe failures leave the old authoritative encrypted bytes
            // untouched; the pending registration remains available to retry.
            throw;
        }
    }

    internal static async Task InstallPreparedRegistrationAsync(InstallRegistrationState registration,
        ISecretStore userStore, bool clearUserAfterSuccess, Func<Task> installService,
        Func<CancellationToken, Task<AgentLocalControlResponse>> adopt, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        await installService().ConfigureAwait(false);
        if (registration.StagedFromUserScope)
        {
            var result = await adopt(ct).ConfigureAwait(false);
            if (!result.Success)
                throw new InvalidOperationException($"Service enrollment requires attention ({result.Code}).");
        }
        if (clearUserAfterSuccess)
            await userStore.ClearAsync(ct).ConfigureAwait(false);
    }

    public static void UninstallOrThrow()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        PreserveMachineRegistrationForUserAsync(
            new DpapiSecretStore(SecretStoreScope.Machine),
            new DpapiSecretStore(SecretStoreScope.User),
            File.Exists(DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.Machine)),
            cts.Token).GetAwaiter().GetResult();

        ServiceInstaller.UninstallOrThrow();

        AgentServiceLocalState.ClearMachineStateAsync(cts.Token).GetAwaiter().GetResult();
    }

    public static void UnregisterDeviceOrThrow()
    {
        static Task<bool> SelfDeactivate(ISecretStore store, string reasonCode, string reason, CancellationToken ct)
            => AgentBackendLifecycle.TrySelfDeactivateAsync(store, reasonCode, reason, ct);

        if (Elevation.IsAdministrator())
        {
            var state = AgentStatus.GetService();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            var adminUserStore = new DpapiSecretStore(SecretStoreScope.User);
            if (state.Installed)
            {
                var retired = AgentLocalControlClient.SendAsync(new("unregister"), cts.Token).GetAwaiter().GetResult();
                if (!retired.Success)
                    throw new InvalidOperationException($"Service unregister did not complete ({retired.Code}); registration was preserved.");
                ServiceInstaller.UninstallOrThrow();
            }
            else if (File.Exists(DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.Machine)))
            {
                throw new InvalidOperationException("Restore the service before unregistering its machine identity.");
            }
            else
            {
                var adminDeactivated = DeactivateAndClearRegistrationAsync(
                    adminUserStore,
                    SelfDeactivate,
                    cts.Token).GetAwaiter().GetResult();
                if (!adminDeactivated)
                    throw new InvalidOperationException("No registration could be deactivated.");
            }

            AgentServiceLocalState.ClearMachineStateAsync(cts.Token).GetAwaiter().GetResult();
            adminUserStore.ClearAsync(cts.Token).GetAwaiter().GetResult();
            return;
        }

        if (AgentStatus.GetService().Installed)
            throw new InvalidOperationException("Service is installed. Run this command as administrator to remove service registration completely.");

        using var userCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var userStore = new DpapiSecretStore(SecretStoreScope.User);
        var userDeactivated = DeactivateAndClearRegistrationAsync(
            userStore,
            SelfDeactivate,
            userCts.Token).GetAwaiter().GetResult();
        if (!userDeactivated)
            throw new InvalidOperationException("No registration could be deactivated; local state was preserved.");
    }
}
