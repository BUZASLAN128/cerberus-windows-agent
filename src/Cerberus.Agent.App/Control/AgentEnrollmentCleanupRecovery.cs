using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using System.IO;

namespace Cerberus.Agent.App.Control;

internal static class AgentEnrollmentCleanupRecovery
{
    internal static async Task OnServiceStartAsync(IAgentLifecycleStateStore lifecycle, IAgentLogger log, CancellationToken ct)
    {
        if (await TryCompleteAsync(lifecycle, new DpapiSecretStore(SecretStoreScope.Machine), ct).ConfigureAwait(false) == false)
            log.Warn("Committed enrollment legacy revoke cleanup remains pending.");
    }

    internal static async Task<bool?> TryCompleteAsync(IAgentLifecycleStateStore lifecycle,
        ISecretStore secrets, CancellationToken ct)
    {
        using var fence = await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false);
        return await UnderFenceAsync(lifecycle, secrets, ct).ConfigureAwait(false);
    }

    internal static async Task<bool?> UnderFenceAsync(IAgentLifecycleStateStore lifecycle,
        ISecretStore secrets, CancellationToken ct,
        Func<string, AgentEnrollmentRevokeCleanupStore>? cleanupStore = null,
        Func<string, AgentSignedStateStore>? signedStateStore = null)
    {
        var snapshot = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
        if (snapshot.State != AgentLifecycleState.Active || !snapshot.QuiescenceComplete) return null;
        foreach (var product in new[] { AgentProducts.Cerberus, AgentProducts.Secondary })
        {
            var cleanup = cleanupStore?.Invoke(product) ?? AgentEnrollmentRevokeCleanupStore.ForProduct(product);
            AgentEnrollmentRevokeCleanup? record;
            try { record = cleanup.Read(); }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidOperationException)
            {
                return false; // A damaged obligation cannot prevent the dormant credential path from starting.
            }
            if (record is null || record.Generation != snapshot.Generation || record.Nonce != snapshot.LastEnrollmentNonce)
                continue;
            AgentIdentity identity;
            try { identity = (await secrets.LoadAsync(ct).ConfigureAwait(false)).Identity; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                System.Security.Cryptography.CryptographicException or InvalidOperationException or System.Text.Json.JsonException)
            {
                return false; // Keep the receipt; startup's credential handler owns the dormant transition.
            }
            if (record.Product != product || identity.Product != product || identity.AgentId != record.AgentId)
                return false;
            var state = signedStateStore?.Invoke(product) ?? new AgentSignedStateStore(AgentSignedStateStore.DefaultPathForProduct(product));
            var complete = false;
            bool current;
            try
            {
                current = await lifecycle.ExecuteIfCurrentAsync(snapshot.Generation, _ =>
                {
                    complete = cleanup.TryComplete(snapshot, identity.AgentId,
                        id => state.TryClearLegacyRevokeAfterEnrollment(id, verifiedEnrollment: true));
                    return Task.CompletedTask;
                }, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidOperationException)
            {
                return false;
            }
            return current && complete;
        }
        return null;
    }
}
