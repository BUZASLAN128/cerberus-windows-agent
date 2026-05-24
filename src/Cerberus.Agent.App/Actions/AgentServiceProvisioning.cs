using Cerberus.Agent.Core;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Security;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.App.Actions;

internal sealed record AgentServiceCredentialPromotionResult(string AgentId, string TenantId);

internal static class AgentServiceCredentialBridge
{
    public static Task<AgentServiceCredentialPromotionResult> PromoteUserSecretsToMachineAsync(CancellationToken ct)
        => PromoteAndClearSourceAsync(
            new DpapiSecretStore(SecretStoreScope.User),
            new DpapiSecretStore(SecretStoreScope.Machine),
            ct);

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
        await new DpapiSecretStore(SecretStoreScope.Machine).ClearAsync(ct).ConfigureAwait(false);

        var baseDir = DpapiSecretStore.GetDefaultBaseDir(SecretStoreScope.Machine);
        DeleteFileIfExists(Path.Combine(baseDir, "idempotency.json"));
        DeleteFileIfExists(Path.Combine(baseDir, "telemetry-offline.json"));
        DeleteDirectoryIfExists(Path.Combine(baseDir, "updates"));
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
    internal sealed record InstallRegistrationState(bool PromotedFromUserScope);

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

    internal static async Task<InstallRegistrationState> EnsureMachineRegistrationForInstallAsync(
        ISecretStore userStore,
        ISecretStore machineStore,
        CancellationToken ct)
    {
        if (await HasCompleteRegistrationAsync(userStore, ct).ConfigureAwait(false))
        {
            await AgentServiceCredentialBridge.PromoteAsync(userStore, machineStore, ct).ConfigureAwait(false);
            return new InstallRegistrationState(PromotedFromUserScope: true);
        }

        if (await HasCompleteRegistrationAsync(machineStore, ct).ConfigureAwait(false))
            return new InstallRegistrationState(PromotedFromUserScope: false);

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

    public static void InstallOrThrow()
    {
        if (!Elevation.IsAdministrator())
            throw new InvalidOperationException("Administrator privileges are required for service install/uninstall.");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var userStore = new DpapiSecretStore(SecretStoreScope.User);
        var machineStore = new DpapiSecretStore(SecretStoreScope.Machine);

        AgentLegalConsent.RequireCurrentInstallConsent();
        var userRegistrationAvailable = HasCompleteRegistrationAsync(userStore, cts.Token)
            .GetAwaiter()
            .GetResult();
        if (userRegistrationAvailable)
            AgentClaimGate.RequireClaimedForServiceInstall(userStore, cts.Token);

        var registrationState = EnsureMachineRegistrationForInstallAsync(userStore, machineStore, cts.Token)
            .GetAwaiter()
            .GetResult();
        try
        {
            if (!userRegistrationAvailable)
                AgentClaimGate.RequireClaimedForServiceInstall(machineStore, cts.Token);
            AgentLegalConsent.EnsureMachineConsentForInstall();
            ServiceInstaller.InstallOrThrow();
            if (registrationState.PromotedFromUserScope)
                userStore.ClearAsync(cts.Token).GetAwaiter().GetResult();
        }
        catch
        {
            if (registrationState.PromotedFromUserScope)
                machineStore.ClearAsync(cts.Token).GetAwaiter().GetResult();
            throw;
        }
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
        if (Elevation.IsAdministrator())
        {
            var state = AgentStatus.GetService();
            if (state.Installed)
                ServiceInstaller.UninstallOrThrow();

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            if (File.Exists(DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.Machine)))
            {
                _ = AgentBackendLifecycle.TrySelfDeactivateAsync(
                    new DpapiSecretStore(SecretStoreScope.Machine),
                    reasonCode: "agent_unregister_device",
                    reason: "Device unregistered from Windows agent",
                    ct: cts.Token).GetAwaiter().GetResult();
            }

            AgentServiceLocalState.ClearMachineStateAsync(cts.Token).GetAwaiter().GetResult();
            new DpapiSecretStore(SecretStoreScope.User).ClearAsync(cts.Token).GetAwaiter().GetResult();
            return;
        }

        if (AgentStatus.GetService().Installed)
            throw new InvalidOperationException("Service is installed. Run this command as administrator to remove service registration completely.");

        using var userCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var userStore = new DpapiSecretStore(SecretStoreScope.User);
        _ = AgentBackendLifecycle.TrySelfDeactivateAsync(
            userStore,
            reasonCode: "agent_unregister_device",
            reason: "Device unregistered from Windows agent",
            ct: userCts.Token).GetAwaiter().GetResult();
        userStore.ClearAsync(userCts.Token).GetAwaiter().GetResult();
    }
}
