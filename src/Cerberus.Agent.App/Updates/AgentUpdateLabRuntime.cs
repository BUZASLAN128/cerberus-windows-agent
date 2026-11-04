using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>Runtime binding for an explicitly compiled lab campaign; absent metadata has no effect.</summary>
internal static class AgentUpdateLabRuntime
{
    internal sealed record Scope(AgentUpdateLabPolicy Policy, AgentUpdateLabTarget Target, AgentStateDeliveryContext Context);

    internal static Scope? Resolve()
    {
        var policy = AgentUpdateLabPolicy.Parse(AgentUpdateDefaults.LabPolicyB64, AgentUpdateDefaults.ReleaseChannel,
            AgentUpdateDefaults.AllowUnsignedDevBuild, AgentBuildProfile.IsServer);
        if (policy is null) return null;
        if (!AgentBuildConfig.SameEndpoint(AgentBuildConfig.BackendUrl, policy.BackendUrl))
            throw new InvalidOperationException("Development policy cannot change the enrolled backend routing.");
        // Use the same protected registration/lifecycle read as signed-state delivery. No key is exported or logged.
        var lifecycleStore = new DurableAgentLifecycleStateStore();
        var context = EnvelopeWiring.StateDeliveryContext(new DpapiSecretStore(SecretStoreScope.Machine), lifecycleStore)
            (CancellationToken.None).GetAwaiter().GetResult();
        var lifecycle = lifecycleStore.LoadAsync(CancellationToken.None).GetAwaiter().GetResult();
        if (context.Product != AgentProducts.Cerberus || context.Generation != lifecycle.Generation ||
            context.EnrollmentNonce != lifecycle.LastEnrollmentNonce || !lifecycle.QuiescenceComplete ||
            !AgentLifecycleStates.AllowsAutomaticNetwork(lifecycle.State))
            throw new InvalidOperationException("Development update registration is not active.");
        policy.RequireVersion(WindowsDeviceInfo.GetAgentVersion());
        var target = policy.RequireTarget(new(context.AgentId, context.TenantId, context.Product), context.KeyFingerprint,
            DateTimeOffset.UtcNow);
        return new(policy, target, context);
    }

    internal static void RequireLaunch(AgentUpdateJournal active, AgentLifecycleSnapshot lifecycle)
    {
        var scope = Resolve();
        if (scope is null) return;
        RequireLaunchScope(scope, active, lifecycle.Generation, DateTimeOffset.UtcNow);
    }

    internal static void RequireLaunchScope(Scope scope, AgentUpdateJournal active, long lifecycleGeneration, DateTimeOffset now)
    {
        if (active.InstallRequest is not { LocalPolicyId: not null, VerifiedRelease: not null } request ||
            request.LocalPolicyId != scope.Policy.CampaignId || request.LifecycleGeneration != scope.Context.Generation ||
            lifecycleGeneration != scope.Context.Generation || request.ExpiresUtc > scope.Policy.ExpiresAtUtc ||
            request.ExpiresUtc <= now || now < scope.Policy.NotBeforeUtc || now >= scope.Policy.ExpiresAtUtc ||
            request.BoundAttemptId != active.AttemptId ||
            request.TerminalReason is not null)
            throw new InvalidOperationException("Development update campaign authority expired or changed.");
        scope.Policy.RequireVersion(request.VerifiedRelease.Version);
    }

    internal static HttpClientHandler CreateUpdateHandler()
    {
        var handler = BackendTrust.Apply(new HttpClientHandler { MaxAutomaticRedirections = 5 });
        try
        {
            var scope = Resolve();
            if (scope is null) return handler;
            var rootBytes = Convert.FromBase64String(AgentUpdateDefaults.LabFeedRootB64);
            using var root = X509CertificateLoader.LoadCertificate(rootBytes);
            if (!root.Extensions.OfType<X509BasicConstraintsExtension>().Any(c => c.CertificateAuthority))
                throw new InvalidOperationException("Development feed CA is missing.");
            handler.AllowAutoRedirect = false;
            var tls = new AgentUpdateBitsTlsPolicy(AgentUpdateDefaults.LabFeedRootB64, scope.Target.ArtifactPrefix, scope.Policy.ExpiresAtUtc);
            handler.ServerCertificateCustomValidationCallback = (request, certificate, chain, errors) =>
            {
                if (DateTimeOffset.UtcNow >= scope.Policy.ExpiresAtUtc || request.RequestUri is null ||
                    !AgentUpdateManifestValidator.IsAllowedArtifactUri(request.RequestUri, scope.Target.ArtifactPrefix))
                    return false;
                if (errors is not (SslPolicyErrors.None or SslPolicyErrors.RemoteCertificateChainErrors)) return false;
                return tls.ValidateCertificate(request.RequestUri, certificate, chain);
            };
            return handler;
        }
        catch
        {
            handler.Dispose();
            throw;
        }
    }
}
