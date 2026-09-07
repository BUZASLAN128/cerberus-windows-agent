using Cerberus.Agent.Integrations.Ad;
using System.Security.Cryptography;

namespace Cerberus.Agent.Core.Tests;

// Fake authority/directory boundaries prove local denial/replay contracts, not live AD acceptance.
public sealed class ScopedAdCommandHandlerTests
{
    private static readonly AgentIdentity Identity = new("agent", "tenant");
    private static readonly AdUserIdentity ObjectIdentity = new(Guid.NewGuid(), "S-1-5-21-1-2-3-1100");
    private static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-09-06T12:00:00Z");

    [Fact]
    public async Task Dispatcher_IgnoresForgedCache_ConsumesCanonicalPayload_AndReauthorizesEveryReplay()
    {
        var path = Path.Combine(Path.GetTempPath(), "cerberus-ad-support-" + Guid.NewGuid() + ".json");
        try
        {
            var cache = new IdempotencyCache(path, 10, TimeSpan.FromHours(1));
            var command = Command("windows.ad_user.disable");
            cache.Set(command.IdempotencyKey, new("DONE", 0, "forged", null, null));
            var provider = new Provider();
            var count = 0;
            var allow = true;
            var handlers = ScopedAdCommandHandlers.CreateHandlers(Identity, new InMemoryAgentLifecycleStateStore(), (supplied, _) =>
            {
                count++;
                if (!allow) throw new IOException("Authority unavailable");
                return Task.FromResult(new AdCommandAuthority("tenant", "agent", Start.AddSeconds(20), command));
            }, provider, () => Start);
            var dispatcher = new CommandDispatcher(handlers, cache);
            // Supplied payload is intentionally invalid; only the fresh backend payload can reach the provider.
            var supplied = command with { Payload = new { username = "foreign" } };
            Assert.Equal("ad_disabled", Code(await dispatcher.DispatchAsync(supplied, default)));
            Assert.Equal("cerb_test", provider.Target!.Binding.Username);
            Assert.Equal("tenant", provider.Target.Binding.TenantId);
            Assert.Equal("ad_disabled", Code(await dispatcher.DispatchAsync(supplied, default)));
            allow = false;
            var denied = await dispatcher.DispatchAsync(supplied, default);
            Assert.Equal("FAILED", denied.Status);
            Assert.Equal("ad_authority_required", Code(denied));
            Assert.Null(denied.Stdout);
            Assert.Equal(3, count);
            Assert.Equal(2, provider.DisableCount);
            Assert.True(cache.TryGet(command.IdempotencyKey, out var unchanged));
            Assert.Equal("forged", unchanged.Stdout); // AD never writes this unprotected replay store either.
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Theory]
    [InlineData("tenant")]
    [InlineData("agent")]
    [InlineData("lease")]
    [InlineData("expired")]
    [InlineData("generation")]
    public async Task WrongOrStaleAuthority_DoesNotInvokeProvider(string mutation)
    {
        var provider = new Provider();
        var lifecycle = new InMemoryAgentLifecycleStateStore();
        var command = Command("windows.ad_user.disable");
        var handlers = ScopedAdCommandHandlers.CreateHandlers(Identity, lifecycle, async (_, _) =>
        {
            if (mutation == "generation") await lifecycle.SaveAsync(new(AgentLifecycleState.Retired), default);
            return new(mutation == "tenant" ? "other" : "tenant", mutation == "agent" ? "other" : "agent",
                mutation == "expired" ? Start : Start.AddSeconds(20), mutation == "lease" ? command with { LeaseId = "other" } : command);
        }, provider, () => Start);
        var denied = await handlers.Single(h => h.Type == command.Type).HandleAsync(command, default);
        Assert.Equal("FAILED", denied.Status);
        Assert.Equal("ad_authority_required", Code(denied));
        Assert.Null(provider.Target);
    }

    [Fact]
    public async Task DirectAuthorizedEntry_DeniesBypass_AndExpiredActivationCompensatesWithScopedDisable()
    {
        var now = Start;
        var provider = new Provider { OnActivate = () => now = Start.AddSeconds(21) };
        var command = Command("windows.ad_user.create", "activate");
        var handler = (IAuthoritativeCommandExecutionGate)ScopedAdCommandHandlers.CreateHandlers(Identity,
            new InMemoryAgentLifecycleStateStore(), (_, _) => Task.FromResult(new AdCommandAuthority("tenant", "agent", Start.AddSeconds(20), command)),
            provider, () => now).Single(h => h.Type == command.Type);
        Assert.Equal("ad_authority_required", Code(await handler.HandleAuthorizedAsync(command, default)));
        Assert.False(provider.Enabled);
        var result = await handler.HandleAsync(command, default);
        Assert.Equal("ad_authority_required", Code(result));
        Assert.Equal("FAILED", result.Status);
        Assert.False(provider.Enabled);
        Assert.Equal(1, provider.DisableCount);
        Assert.Equal(ObjectIdentity, provider.ExpectedIdentity);
        Assert.True(((Dictionary<string, object?>)result.PostVerify!).ContainsKey("managed_account_id"));
    }

    [Fact]
    public async Task DispatcherActivationTimeout_CompensatesEvenWhileAuthorityRemainsFresh()
    {
        var path = Path.Combine(Path.GetTempPath(), "cerberus-ad-timeout-support-" + Guid.NewGuid() + ".json");
        try
        {
            var provider = new Provider { WaitActivation = ct => Task.Delay(Timeout.InfiniteTimeSpan, ct) };
            var command = Command("windows.ad_user.create", "activate");
            var handlers = ScopedAdCommandHandlers.CreateHandlers(Identity, new InMemoryAgentLifecycleStateStore(),
                (_, _) => Task.FromResult(new AdCommandAuthority("tenant", "agent", Start.AddSeconds(20), command)), provider, () => Start);
            var dispatcher = new CommandDispatcher(handlers, new IdempotencyCache(path, 10, TimeSpan.FromHours(1)));
            var result = await dispatcher.DispatchAsync(command, TimeSpan.FromMilliseconds(20), default);
            Assert.Equal("FAILED", result.Status);
            Assert.Equal("ad_authority_required", Code(result));
            Assert.False(provider.Enabled);
            Assert.Equal(1, provider.DisableCount);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public void ExpiredCredential_IsStructurallyParsed_ButExecutionValidationRejectsIt()
    {
        using var rsa = RSA.Create(2048);
        var request = ScopedAdUserProviderTests.CredentialRequest(rsa) with { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1) };
        var command = Command("windows.ad_user.create", "prepare");
        var payload = (Dictionary<string, object?>)command.Payload!;
        payload["credential_request_id"] = request.CredentialRequestId;
        payload["credential_expires_at"] = request.ExpiresAt.ToString("O");
        payload["rdp_credential_profile_id"] = request.Metadata.CredentialProfileId;
        payload["rdp_tenant_key_id"] = request.Metadata.TenantKeyId;
        payload["rdp_key_version"] = request.Metadata.KeyVersion;
        payload["rdp_public_key_pem"] = request.Metadata.PublicKeyPem;
        payload["rdp_public_key_fingerprint"] = request.Metadata.PublicKeyFingerprint;
        payload["rdp_cipher_alg"] = request.Metadata.CipherAlg;
        payload["rdp_aad"] = request.Metadata.Aad;
        payload["rdp_aad_hash"] = request.Metadata.AadHash;
        var parsed = ScopedAdCommandPayload.Parse(command, Identity);
        Assert.Equal(request, parsed.CredentialRequest);
        Assert.Equal("ad_credential_expired", Assert.Throws<AdOperationDeniedException>(() =>
            ScopedAdUserProvider.ValidateCredentialRequest(parsed.CredentialRequest!)).Code);
    }

    private static AgentCommand Command(string type, string? phase = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["schema_version"] = "agent.ad-user.command.v1", ["managed_account_id"] = Guid.NewGuid().ToString(),
            ["assignment_id"] = Guid.NewGuid().ToString(), ["scope_id"] = Guid.NewGuid().ToString(),
            ["username"] = "cerb_test", ["domain_guid"] = Guid.NewGuid().ToString(), ["ou_guid"] = Guid.NewGuid().ToString(),
            ["domain_dns_name"] = "example.test", ["audit_correlation_id"] = "audit-support", ["reason"] = "support test"
        };
        if (phase is not null) payload["phase"] = phase;
        if (phase != "prepare")
        {
            payload["expected_object_guid"] = ObjectIdentity.ObjectGuid.ToString();
            payload["expected_sid"] = ObjectIdentity.Sid;
        }
        if (phase == "activate") payload["credential_profile_id"] = Guid.NewGuid().ToString();
        return new("command", type, "idempotency", payload, LeaseId: "lease");
    }

    private static string Code(CommandResult result) => (string)((Dictionary<string, object?>)result.PostVerify!)["code"]!;

    private sealed class Provider : IScopedAdUserProvider
    {
        public AdCommandTarget? Target;
        public AdUserIdentity? ExpectedIdentity;
        public int DisableCount;
        public bool Enabled;
        public Action? OnActivate;
        public Func<CancellationToken, Task>? WaitActivation;
        public async Task<AdOperationResult> ActivateAsync(AdCommandTarget target, AdUserIdentity identity, string profile, CancellationToken ct)
        {
            Target = target; ExpectedIdentity = identity; Enabled = true; OnActivate?.Invoke();
            if (WaitActivation is not null) await WaitActivation(ct);
            return new(true, "ad_activated", identity);
        }
        public Task<AdOperationResult> DisableAsync(AdCommandTarget target, AdUserIdentity identity, string reason, CancellationToken ct)
        {
            Target = target; ExpectedIdentity = identity; Enabled = false; DisableCount++;
            return Task.FromResult(new AdOperationResult(true, "ad_disabled", identity));
        }
        public Task<AdOperationResult> PrepareAsync(AdCommandTarget target, AdCredentialRequest request, CancellationToken ct) => throw new NotSupportedException();
        public Task<AdOperationResult> DeleteAsync(AdCommandTarget target, AdUserIdentity identity, bool confirmed, string reason, CancellationToken ct) => throw new NotSupportedException();
        public Task<AdOperationResult> CreateAsync(AdAccountBinding binding, string password, bool activate, CancellationToken ct) => throw new NotSupportedException();
        public Task<AdOperationResult> DisableAsync(AdAccountBinding binding, string reason, CancellationToken ct) => throw new NotSupportedException();
        public Task<AdOperationResult> DeleteAsync(AdAccountBinding binding, bool confirmed, string reason, CancellationToken ct) => throw new NotSupportedException();
    }
}
