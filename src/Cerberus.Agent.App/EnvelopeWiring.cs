using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App;

/// <summary>Service wiring for signed command envelopes (contract v1 (a)): the queue and the heartbeat processor.</summary>
internal static class EnvelopeWiring
{
#if !CERBERUS_SERVER_PROFILE
    private static readonly TimeSpan LegacyCommandTimeout = TimeSpan.FromSeconds(120);
    private const int LegacyCommandConcurrency = 2;
#endif

    /// <summary>The current credential's agent id, read on every call so a re-enrollment rebinds without a restart.</summary>
    public static Func<CancellationToken, Task<string>> CurrentAgentId(ISecretStore secrets)
        => async ct => (await secrets.LoadAsync(ct).ConfigureAwait(false)).Identity.AgentId;

    internal static Func<CancellationToken, Task<string>> CurrentAgentId(ISecretStore secrets,
        IAgentLifecycleStateStore lifecycle, long expectedGeneration, AgentSignedStateStore signedState)
        => signedState.Track(async ct =>
        {
            if ((await lifecycle.LoadAsync(ct).ConfigureAwait(false)).Generation != expectedGeneration)
                throw new AgentRegistrationChangedException();
            var id = await CurrentAgentId(secrets)(ct).ConfigureAwait(false);
            if ((await lifecycle.LoadAsync(ct).ConfigureAwait(false)).Generation != expectedGeneration)
                throw new AgentRegistrationChangedException();
            return id;
        });

#if !CERBERUS_SERVER_PROFILE
    internal static LegacyAsyncCommandProcessor CreateLegacyAsync(AgentApiClient api, CommandDispatcher dispatcher,
        AgentIdentity identity, AgentLifecycleSnapshot lifecycle, Func<CancellationToken, Task<string>> currentAgentId,
        IAgentLogger log)
    {
        // Managed operations retain their existing synchronous authority path; this is observation only.
        var delayLog = Environment.GetEnvironmentVariable("CERBERUS_MANAGED_DELAY_DIAGNOSTIC") == "1" ? log : null;
        return new LegacyAsyncCommandProcessor(api, dispatcher,
            new LegacyHeartbeatCommandProcessor(api, dispatcher, LegacyCommandTimeout, LegacyCommandConcurrency, delayLog),
            CommandReplayStore.OpenLegacyAsyncForEnrollment(identity, lifecycle, log), currentAgentId, log);
    }
#endif

    /// <summary>The background queue for <paramref name="handlers"/>, started; dispose it when the service worker stops.</summary>
    public static EnvelopeExecutionQueue StartQueue(
        AgentApiClient api,
        IEnumerable<ICommandHandler> handlers,
        Func<CancellationToken, Task<string>> currentAgentId,
        AgentSignedStateStore signedState,
        IAgentLogger log,
        string product = AgentProducts.Cerberus)
    {
        var queue = new EnvelopeExecutionQueue(api, new CommandReplayStore(CommandReplayStore.DefaultPathForProduct(product), log: log),
            handlers, currentAgentId, signedState.IsQuarantined, log: log);
        queue.Start();
        return queue;
    }

    /// <summary>
    /// Every heartbeat command goes through the envelope processor. Desktop hands entries without an
    /// envelope to the legacy processor, exactly as the loop did; the server build has no such path.
    /// </summary>
    public static IHeartbeatCommandProcessor CreateProcessor(
        AgentApiClient api,
        EnvelopeExecutionQueue queue,
        CommandDispatcher dispatcher,
        IAgentLogger log,
        string product = AgentProducts.Cerberus,
        IHeartbeatCommandProcessor? legacy = null)
    {
        var anchors = AgentProfileMetadata.LoadProductCommandAnchors(product, ManifestPublicKeyPems(log), log);
#if CERBERUS_SERVER_PROFILE
        return new EnvelopeCommandProcessor(api, anchors, queue, log: log);
#else
        if (product == AgentProducts.Secondary)
            return new EnvelopeCommandProcessor(api, anchors, queue, allowedTypes: EnvelopeTypes.ServerSet, log: log);
        return new EnvelopeCommandProcessor(api, anchors, queue, log: log,
            legacy: legacy ?? new LegacyHeartbeatCommandProcessor(api, dispatcher, LegacyCommandTimeout, LegacyCommandConcurrency));
#endif
    }

    /// <summary>Update manifest keys, so an anchor equal to one of them is dropped and never authorizes commands.
    /// When no update trust is configured, the embedded manifest keys still count.</summary>
    internal static IReadOnlyList<string> ManifestPublicKeyPems(IAgentLogger log)
    {
        try
        {
            return AgentUpdateTrustFactory.BuildTrust(log).ManifestPublicKeyPems;
        }
        catch (InvalidOperationException)
        {
            return AgentUpdateTrustFactory.ResolveUpdateManifestPublicKeys(
                AgentUpdateDefaults.ManifestPublicKeysB64, null, null, null, null, log);
        }
    }
}
