using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using System.IO;

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

        var (verifiedIdentity, _, _, verifiedBackendUrl, _, _) =
            await machineStore.LoadAsync(ct).ConfigureAwait(false);

        if (!string.Equals(verifiedIdentity.AgentId, identity.AgentId, StringComparison.Ordinal) ||
            !string.Equals(verifiedIdentity.TenantId, identity.TenantId, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(verifiedBackendUrl))
        {
            throw new InvalidOperationException("Machine-scope agent registration verification failed.");
        }

        return new AgentServiceCredentialPromotionResult(identity.AgentId, identity.TenantId);
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

internal static class AgentServiceProvisioning
{
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

    public static void InstallOrThrow()
    {
        if (!Elevation.IsAdministrator())
            throw new InvalidOperationException("Administrator privileges are required for service install/uninstall.");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var userStore = new DpapiSecretStore(SecretStoreScope.User);
        var machineStore = new DpapiSecretStore(SecretStoreScope.Machine);

        AgentServiceCredentialBridge.PromoteAsync(userStore, machineStore, cts.Token).GetAwaiter().GetResult();
        try
        {
            ServiceInstaller.InstallOrThrow();
            userStore.ClearAsync(cts.Token).GetAwaiter().GetResult();
        }
        catch
        {
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
            AgentServiceLocalState.ClearMachineStateAsync(cts.Token).GetAwaiter().GetResult();
            new DpapiSecretStore(SecretStoreScope.User).ClearAsync(cts.Token).GetAwaiter().GetResult();
            return;
        }

        if (AgentStatus.GetService().Installed)
            throw new InvalidOperationException("Service is installed. Run this command as administrator to remove service registration completely.");

        using var userCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        new DpapiSecretStore(SecretStoreScope.User).ClearAsync(userCts.Token).GetAwaiter().GetResult();
    }
}
