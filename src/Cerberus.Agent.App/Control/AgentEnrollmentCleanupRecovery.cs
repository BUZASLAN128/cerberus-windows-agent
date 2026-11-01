using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

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
            var record = cleanup.Read();
            if (record is null || record.Generation != snapshot.Generation || record.Nonce != snapshot.LastEnrollmentNonce)
                continue;
            var identity = (await secrets.LoadAsync(ct).ConfigureAwait(false)).Identity;
            if (record.Product != product || identity.Product != product || identity.AgentId != record.AgentId)
                return false;
            var state = signedStateStore?.Invoke(product) ?? new AgentSignedStateStore(AgentSignedStateStore.DefaultPathForProduct(product));
            var complete = false;
            var current = await lifecycle.ExecuteIfCurrentAsync(snapshot.Generation, _ =>
            {
                complete = cleanup.TryComplete(snapshot, identity.AgentId,
                    id => state.TryClearLegacyRevokeAfterEnrollment(id, verifiedEnrollment: true));
                return Task.CompletedTask;
            }, ct).ConfigureAwait(false);
            return current && complete;
        }
        return null;
    }
}
