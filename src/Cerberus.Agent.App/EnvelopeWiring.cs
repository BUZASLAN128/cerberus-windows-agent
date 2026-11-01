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

    internal static Func<CancellationToken, Task<AgentRevokeRegistration>> RegistrationContext(
        ISecretStore secrets, IAgentLifecycleStateStore lifecycle)
        => async ct =>
        {
            var before = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
            var identity = (await secrets.LoadAsync(ct).ConfigureAwait(false)).Identity;
            var after = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
            if (before.Generation != after.Generation || before.LastEnrollmentNonce != after.LastEnrollmentNonce)
                throw new AgentRegistrationChangedException();
            return new AgentRevokeRegistration(identity.AgentId, identity.TenantId, after.LastEnrollmentNonce);
        };

    internal static Func<CancellationToken, Task<AgentStateDeliveryContext>> StateDeliveryContext(
        ISecretStore secrets, IAgentLifecycleStateStore lifecycle)
        => async ct =>
        {
            var before = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
            var loaded = await secrets.LoadAsync(ct).ConfigureAwait(false);
            var after = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
            if (before.Generation != after.Generation || before.LastEnrollmentNonce != after.LastEnrollmentNonce)
                throw new AgentRegistrationChangedException();
            return new(loaded.Identity.AgentId, loaded.Identity.TenantId, after.Generation, after.LastEnrollmentNonce,
                loaded.Identity.Product, AgentKeyFingerprint.FromPrivateKeyPem(loaded.PrivateKeyPem));
        };

    internal static bool HasCommandTrust(string product, IAgentLogger log)
        => AgentProfileMetadata.LoadProductCommandAnchors(product, ManifestPublicKeyPems(log), log).Count > 0;

#if !CERBERUS_SERVER_PROFILE
    internal static LegacyAsyncCommandProcessor CreateLegacyAsync(AgentApiClient api, CommandDispatcher dispatcher,
        AgentIdentity identity, AgentLifecycleSnapshot lifecycle, Func<CancellationToken, Task<string>> currentAgentId,
        AgentSignedStateStore signedState, IAgentLogger log, string? keyFingerprint = null)
    {
        // Managed operations retain their existing synchronous authority path; this is observation only.
        var delayLog = Environment.GetEnvironmentVariable("CERBERUS_MANAGED_DELAY_DIAGNOSTIC") == "1" ? log : null;
        return new LegacyAsyncCommandProcessor(api, dispatcher,
            new LegacyHeartbeatCommandProcessor(api, dispatcher, LegacyCommandTimeout, LegacyCommandConcurrency, delayLog),
            CommandReplayStore.OpenLegacyAsyncForEnrollment(identity, lifecycle, log, keyFingerprint: keyFingerprint), currentAgentId, log,
            recoveryControlOnly: () => signedState.RecoveryControlOnly);
    }
#endif

    /// <summary>The background queue for <paramref name="handlers"/>, started; dispose it when the service worker stops.</summary>
    public static EnvelopeExecutionQueue StartQueue(
        AgentApiClient api,
        IEnumerable<ICommandHandler> handlers,
        Func<CancellationToken, Task<string>> currentAgentId,
        AgentSignedStateStore signedState,
        IAgentLogger log,
        AgentStateDeliveryContext controlContext,
        Func<CancellationToken, Task<AgentStateDeliveryContext>> currentControlContext,
        string product = AgentProducts.Cerberus)
    {
        var store = new CommandReplayStore(CommandReplayStore.DefaultPathForProduct(product), log: log, enrollmentEstablished: true);
        if (!store.IsAvailable) log.Warn("Command replay storage unavailable; signed commands remain disabled.");
        var queue = new EnvelopeExecutionQueue(api, store,
            handlers, currentAgentId, signedState.IsQuarantined, log: log, signedState: signedState,
            controlContext: controlContext, currentControlContext: currentControlContext);
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
        IHeartbeatCommandProcessor? legacy = null,
        IReadOnlyList<CommandTrustAnchor>? commandAnchors = null)
    {
        var anchors = commandAnchors ?? AgentProfileMetadata.LoadProductCommandAnchors(product, ManifestPublicKeyPems(log), log);
        if (product == AgentProducts.Secondary)
            return new EnvelopeCommandProcessor(api, anchors, queue,
                allowedTypes: queue.HandlerTypes.ToHashSet(StringComparer.Ordinal), log: log);
#if CERBERUS_SERVER_PROFILE
        return new EnvelopeCommandProcessor(api, anchors, queue, log: log);
#else
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
