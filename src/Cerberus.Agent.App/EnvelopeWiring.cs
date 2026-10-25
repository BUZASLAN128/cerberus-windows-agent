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

    /// <summary>The background queue for <paramref name="handlers"/>, started; dispose it when the service worker stops.</summary>
    public static EnvelopeExecutionQueue StartQueue(
        AgentApiClient api,
        IEnumerable<ICommandHandler> handlers,
        Func<CancellationToken, Task<string>> currentAgentId,
        AgentSignedStateStore signedState,
        IAgentLogger log)
    {
        var queue = new EnvelopeExecutionQueue(api, new CommandReplayStore(CommandReplayStore.DefaultPath(), log: log),
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
        IAgentLogger log)
    {
        var anchors = AgentProfileMetadata.LoadCommandAnchors(ManifestPublicKeyPems(log), log);
#if CERBERUS_SERVER_PROFILE
        return new EnvelopeCommandProcessor(api, anchors, queue, log: log);
#else
        return new EnvelopeCommandProcessor(api, anchors, queue, log: log,
            legacy: new LegacyHeartbeatCommandProcessor(api, dispatcher, LegacyCommandTimeout, LegacyCommandConcurrency));
#endif
    }

    /// <summary>Update manifest keys, so an anchor equal to one of them is dropped and never authorizes commands.
    /// When no update trust is configured, the embedded manifest keys still count.</summary>
    private static IReadOnlyList<string> ManifestPublicKeyPems(IAgentLogger log)
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
