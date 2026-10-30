namespace Cerberus.Agent.Core;

public sealed partial class AgentApiClient
{
    private async Task EnsureAutomaticNetworkAllowedAsync(CancellationToken ct)
    {
        if (_lifecycleState is null)
            return;

        if (_expectedGeneration is { } expected)
        {
            var snapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
            if (snapshot.Generation != expected) throw new AgentLifecycleDormantException(snapshot);
        }

        if (_manualOperation)
        {
            var manualSnapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
            if (manualSnapshot.State is AgentLifecycleState.Retired or AgentLifecycleState.NeedsReenrollment || !manualSnapshot.QuiescenceComplete)
                throw new AgentLifecycleDormantException(manualSnapshot);
            return;
        }

        await new AgentLifecycleController(_lifecycleState, _secrets)
            .EnsureAutomaticNetworkAllowedAsync(ct)
            .ConfigureAwait(false);
    }

}
