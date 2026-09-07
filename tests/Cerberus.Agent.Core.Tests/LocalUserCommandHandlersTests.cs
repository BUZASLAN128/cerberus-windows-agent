using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cerberus.Agent.Core.Tests;

public sealed class LocalUserCommandHandlersTests
{
    private static int _rateLimitProbeCalls;

    [Fact]
    public async Task CreateManagedUser_DeniesCreateWhenPolicyDisabled()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateDisabled)
            .Single(item => item.Type == "windows.local_user.create");
        var command = CreateCommand("policy-closed") with { Type = handler.Type };

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("disabled by local agent policy", result.Stderr);
        Assert.Contains("local_user_create_disabled_by_policy", Convert.ToString(result.PostVerify));
    }

    [Fact]
    public async Task CreateManagedUser_PolicyDenialBindsManagedAccountAndCredentialIdentifiers()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateDisabled)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem-policy-identifiers",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_request_id = "credential-request-id",
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        var postVerify = JsonSerializer.SerializeToElement(result.PostVerify);
        Assert.Equal("local_user_create_disabled_by_policy", postVerify.GetProperty("code").GetString());
        Assert.Equal("before_execution", postVerify.GetProperty("execution_stage").GetString());
        Assert.Equal("managed-account-id", postVerify.GetProperty("managed_account_id").GetString());
        Assert.Equal("credential-request-id", postVerify.GetProperty("credential_request_id").GetString());

        var directAuthorized = await Assert.IsAssignableFrom<ICommandExecutionGate>(handler)
            .HandleAuthorizedAsync(command, CancellationToken.None);
        var directPostVerify = JsonSerializer.SerializeToElement(directAuthorized.PostVerify);
        Assert.Equal("managed-account-id", directPostVerify.GetProperty("managed_account_id").GetString());
        Assert.Equal("credential-request-id", directPostVerify.GetProperty("credential_request_id").GetString());
    }

    [Fact]
    public async Task Dispatcher_ReplaysCachedCreateAfterLocalPolicyCloses_ButManifestStillAuthorizesReplay()
    {
        var now = DateTimeOffset.Parse("2026-09-06T12:00:00Z");
        var manifest = FreshManifest(now);
        var policy = new ManagedAccountManifestPolicy(
            new AgentIdentity("agent", "tenant"),
            new InMemoryAgentLifecycleStateStore(),
            _ => Task.FromResult(manifest),
            new NoopManifestReconciler(),
            now: () => now);
        await policy.RefreshAsync(ManifestHeartbeat(manifest), CancellationToken.None);

        var command = CreateCommand("cached-replay");
        var cached = new CommandResult(
            "DONE",
            0,
            null,
            null,
            new
            {
                code = "created",
                managed_account_id = "managed-account-id",
                credential_request_id = "credential-request-id",
            });
        var path = Path.Combine(Path.GetTempPath(), "cerberus-local-replay-" + Guid.NewGuid() + ".json");
        try
        {
            var cache = new IdempotencyCache(path, 10, TimeSpan.FromHours(1));
            cache.Set(command.IdempotencyKey, cached);
            var dispatcher = new CommandDispatcher(
                LocalUserCommandHandlers.CreateDefaultHandlers(
                    policyResolver: () => LocalUserCommandPolicy.CreateDisabled,
                    manifest: policy),
                cache);

            var malformed = await dispatcher.DispatchAsync(
                command with { Payload = new { username = "cerb_sennu_k7m2q6x4" } },
                CancellationToken.None);
            Assert.NotSame(cached, malformed);
            Assert.Contains("missing_audit_correlation", Convert.ToString(malformed.PostVerify));

            var replay = await dispatcher.DispatchAsync(command, CancellationToken.None);

            Assert.Same(cached, replay);

            now = now.AddSeconds(301);
            await policy.RefreshAsync(ManifestHeartbeat(manifest), CancellationToken.None);
            var revoked = await dispatcher.DispatchAsync(command, CancellationToken.None);
            Assert.NotSame(cached, revoked);
            var revokedPostVerify = JsonSerializer.SerializeToElement(revoked.PostVerify);
            Assert.Equal("managed_account_manifest_required", revokedPostVerify.GetProperty("code").GetString());
            Assert.Equal("before_execution", revokedPostVerify.GetProperty("execution_stage").GetString());
            Assert.Equal("managed-account-id", revokedPostVerify.GetProperty("managed_account_id").GetString());
            Assert.Equal("credential-request-id", revokedPostVerify.GetProperty("credential_request_id").GetString());
            Assert.Equal("created", revokedPostVerify.GetProperty("mutation_result_code").GetString());
            Assert.Equal("DONE", revokedPostVerify.GetProperty("mutation_result_status").GetString());
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task CreateManagedUser_StartupOpenThenRuntimeCloseDeniesBeforeNativeMutation()
    {
        var current = LocalUserCommandPolicy.CreateEnabledPolicy;
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(policyResolver: () => current)
            .Single(item => item.Type == "windows.local_user.create");

        var initiallyOpen = await handler.HandleAsync(CreateCommand("open"), CancellationToken.None);
        current = LocalUserCommandPolicy.CreateDisabled;
        var runtimeClosed = await handler.HandleAsync(CreateCommand("closed"), CancellationToken.None);

        Assert.Contains("managed_account_manifest_required", Convert.ToString(initiallyOpen.PostVerify));
        Assert.Contains("local_user_create_disabled_by_policy", Convert.ToString(runtimeClosed.PostVerify));
    }

    [Fact]
    public async Task CreateManagedUser_StartupClosedThenRuntimeOpenRechecksAndPermitsPolicyGate()
    {
        var current = LocalUserCommandPolicy.CreateDisabled;
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(policyResolver: () => current)
            .Single(item => item.Type == "windows.local_user.create");

        var initiallyClosed = await handler.HandleAsync(CreateCommand("closed"), CancellationToken.None);
        current = LocalUserCommandPolicy.CreateEnabledPolicy;
        var runtimeOpen = await handler.HandleAsync(CreateCommand("open"), CancellationToken.None);

        Assert.Contains("local_user_create_disabled_by_policy", Convert.ToString(initiallyClosed.PostVerify));
        Assert.Contains("managed_account_manifest_required", Convert.ToString(runtimeOpen.PostVerify));
    }

    [Fact]
    public async Task CreateManagedUser_UnknownPolicyFailsClosedAndDisableDeleteRemainRegistered()
    {
        var handlers = LocalUserCommandHandlers
            .CreateDefaultHandlers(policyResolver: () => LocalUserCommandPolicy.UnknownPolicy);
        var create = handlers.Single(item => item.Type == "windows.local_user.create");

        var result = await create.HandleAsync(CreateCommand("unknown"), CancellationToken.None);

        Assert.Contains("local_user_create_policy_unknown", Convert.ToString(result.PostVerify));
        Assert.Equal("before_execution",
            JsonSerializer.SerializeToElement(result.PostVerify).GetProperty("execution_stage").GetString());
        Assert.Contains(handlers, item => item.Type == "windows.local_user.disable");
        Assert.Contains(handlers, item => item.Type == "windows.local_user.delete");
    }

    [Fact]
    public async Task CreateManagedUser_ManifestDenyBindsPayloadIdsAndBeforeStage()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(policyResolver: () => LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "manifest-deny",
            handler.Type,
            "manifest-deny-idempotency",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_request_id = "credential-request-id",
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);
        var postVerify = JsonSerializer.SerializeToElement(result.PostVerify);

        Assert.Equal("managed_account_manifest_required", postVerify.GetProperty("code").GetString());
        Assert.Equal("before_execution", postVerify.GetProperty("execution_stage").GetString());
        Assert.Equal("managed-account-id", postVerify.GetProperty("managed_account_id").GetString());
        Assert.Equal("assignment-id", postVerify.GetProperty("assignment_id").GetString());
        Assert.Equal("marker-id", postVerify.GetProperty("marker_id").GetString());
        Assert.Equal("credential-request-id", postVerify.GetProperty("credential_request_id").GetString());
    }

    [Fact]
    public async Task CreateManagedUser_RejectsUsernameWithoutManagedPrefix()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "Administrator", audit_correlation_id = "audit-id" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("local account limits", result.Stderr);
    }

    [Fact]
    public async Task DeleteManagedUser_RejectsMissingAuditCorrelation()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.delete");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "cerb_sennu_k7m2q6x4" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("audit correlation", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_AcceptsManagedUsernameShapeBeforeAuditGate()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "cerb_sennu_k7m2q6x4" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("audit correlation", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsUsernameOverWindowsLocalLimit()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "cerb_sennu_k7m2q6x4x", audit_correlation_id = "audit-id" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("local account limits", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsManagedUsernameWithInvalidBase32Suffix()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new { username = "cerb_sennu_k7m2q9x4", audit_correlation_id = "audit-id" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("local account limits", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsCurrentManagedUsernameWithoutMarkerIdentity()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("assignment, account, membership, and marker", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsInvalidCredentialPublicKeyBeforeMutation()
    {
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_public_key_pem = "not-a-pem",
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("public key", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsWeakCredentialPublicKeyBeforeMutation()
    {
        using var rsa = RSA.Create(1024);
        var publicPem = PublicKeyPem(rsa);
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_public_key_pem = publicPem,
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("2048", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsCredentialPublicKeyWithoutFingerprintBeforeMutation()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = PublicKeyPem(rsa);
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_public_key_pem = publicPem,
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("fingerprint", result.Stderr);
    }


    [Fact]
    public async Task CreateManagedUser_RejectsCredentialPublicKeyFingerprintMismatchBeforeMutation()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = PublicKeyPem(rsa);
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_public_key_pem = publicPem,
                credential_key_fingerprint = new string('0', 64),
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("fingerprint", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsInvalidRdpPublicKeyBeforeMutation()
    {
        var aad = "tenant|credential|rdp|1";
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                rdp_credential_profile_id = Guid.NewGuid().ToString(),
                rdp_tenant_key_id = "tenant-key",
                rdp_key_version = 1,
                rdp_public_key_pem = "not-a-pem",
                rdp_cipher_alg = "aes256gcm+rsa-oaep",
                rdp_aad = aad,
                rdp_aad_hash = Sha256Hex(aad),
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("RDP credential public key", result.Stderr);
    }

    [Fact]
    public async Task CreateManagedUser_RejectsRdpAadHashMismatchBeforeMutation()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = PublicKeyPem(rsa);
        var handler = LocalUserCommandHandlers
            .CreateDefaultHandlers(LocalUserCommandPolicy.CreateEnabledPolicy)
            .Single(item => item.Type == "windows.local_user.create");
        var command = new AgentCommand(
            "cmd-id",
            handler.Type,
            "idem",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                rdp_credential_profile_id = Guid.NewGuid().ToString(),
                rdp_tenant_key_id = "tenant-key",
                rdp_key_version = 1,
                rdp_public_key_pem = publicPem,
                rdp_public_key_fingerprint = Sha256HexAscii(publicPem),
                rdp_cipher_alg = "aes256gcm+rsa-oaep",
                rdp_aad = "tenant|credential|rdp|1",
                rdp_aad_hash = new string('0', 64),
            });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("AAD hash", result.Stderr);
    }

    [Fact]
    public void BuildRdpCredentialEnvelope_EncryptsPasswordWithoutPlaintextFields()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = PublicKeyPem(rsa);
        var credentialId = Guid.NewGuid().ToString();
        var aad = $"tenant-id|{credentialId}|rdp|1";
        var payload = LocalUserPayload(
            username: "cerb_sennu_k7m2q6x4",
            credentialProfileId: credentialId,
            tenantKeyId: "tenant-key",
            publicPem: publicPem,
            aad: aad);
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("BuildRdpCredentialEnvelope", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var envelope = Assert.IsType<Dictionary<string, object?>>(
            method.Invoke(null, new[] { "S3cure!Password42", payload }));

        Assert.Equal("password", envelope["auth_type"]);
        Assert.Equal(credentialId, envelope["credential_id"]);
        Assert.Equal("cerb_sennu_k7m2q6x4", envelope["username_hint"]);
        Assert.Equal("tenant-key", envelope["tenant_key_id"]);
        Assert.Equal("aes256gcm+rsa-oaep", envelope["cipher_alg"]);
        Assert.DoesNotContain("S3cure!Password42", Convert.ToString(envelope["ciphertext"]));

        var wrappedDek = Convert.FromBase64String(Assert.IsType<string>(envelope["wrapped_dek"]));
        var nonce = Convert.FromBase64String(Assert.IsType<string>(envelope["cipher_nonce"]));
        var cipherWithTag = Convert.FromBase64String(Assert.IsType<string>(envelope["ciphertext"]));
        var dek = rsa.Decrypt(wrappedDek, RSAEncryptionPadding.OaepSHA256);
        var ciphertext = cipherWithTag[..^16];
        var tag = cipherWithTag[^16..];
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(dek, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(aad));
        var json = Encoding.UTF8.GetString(plaintext);
        Assert.Contains("S3cure!Password42", json);
        Assert.Contains("cerb_sennu_k7m2q6x4", json);
    }

    [Fact]
    public void GeneratePassword_HasNoFixedSuffixAndSatisfiesComplexity()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("GeneratePassword", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var password = Assert.IsType<string>(method.Invoke(null, Array.Empty<object>()));

        Assert.True(password.Length >= 24);
        Assert.False(password.EndsWith("aA1!", StringComparison.Ordinal));
        Assert.Matches("[a-z]", password);
        Assert.Matches("[A-Z]", password);
        Assert.Matches("[0-9]", password);
        Assert.Matches("[!@#$%^*\\-_+=]", password);
    }

    [Fact]
    public void ManagedMarkerToken_IncludesTerminatorToPreventPrefixMatch()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("ManagedMarkerToken", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var marker = Assert.IsType<string>(method.Invoke(null, ["123"]));
        var prefixedMarker = Assert.IsType<string>(method.Invoke(null, ["cerberus-managed-local-user:123"]));
        var longerMarkerDescription = "cerberus-managed-local-user:12345; assignment=a; account=b";

        Assert.Equal("cerberus-managed-local-user:123;", marker);
        Assert.Equal(marker, prefixedMarker);
        Assert.DoesNotContain(marker, longerMarkerDescription, StringComparison.Ordinal);
    }

    [Fact]
    public void ManagedDescription_DoesNotExposeInternalMarkerOrIds()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("ManagedDescription", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var payload = LocalUserPayload(
            "cerb_sennu_k7m2q6x4",
            "credential-profile-id",
            "tenant-key-id",
            "public-key",
            "aad");
        var description = Assert.IsType<string>(method.Invoke(null, [payload]));

        Assert.Equal("Cerberus managed local account.", description);
        Assert.DoesNotContain("cerberus-managed-local-user", description, StringComparison.Ordinal);
        Assert.DoesNotContain("assignment-id", description, StringComparison.Ordinal);
        Assert.DoesNotContain("account-id", description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(0, true)]
    [InlineData(0x0202, false)]
    [InlineData(0x0202, true)]
    public void ApplyManagedPasswordPolicyFlags_OnlyExplicitEnableClearsDisabledFlag(int originalFlags, bool enableAccount)
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("ApplyManagedPasswordPolicyFlags", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var flags = Assert.IsType<int>(method.Invoke(null, [originalFlags, enableAccount]));

        Assert.True((flags & 0x0040) != 0);
        Assert.True((flags & 0x10000) != 0);
        Assert.Equal(enableAccount ? 0 : originalFlags & 0x0002, flags & 0x0002);
        Assert.Equal(originalFlags & ~0x0002, flags & originalFlags & ~0x0002);
    }

    [Theory]
    [InlineData(false, false, false, true)]
    [InlineData(false, false, true, true)]
    [InlineData(false, true, false, true)]
    [InlineData(false, true, true, true)]
    [InlineData(true, false, false, false)]
    [InlineData(true, false, true, false)]
    [InlineData(true, true, false, false)]
    [InlineData(true, true, true, true)]
    public void ShouldGrantRemoteDesktopMembership_OnlyExplicitEnableMayGrantForExistingUser(
        bool existingUser,
        bool enableAccountExplicit,
        bool enableAccount,
        bool expected)
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("ShouldGrantRemoteDesktopMembership", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        var result = Assert.IsType<bool>(method.Invoke(
            null,
            [existingUser, enableAccountExplicit, enableAccount]));

        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(null, true, false)]
    [InlineData(false, true, false)]
    [InlineData(true, true, true)]
    [InlineData("true", false, false)]
    public void CreatePayload_EnableIntentDefaultsClosedAndRequiresBoolean(object? intent, bool valid, bool expectedEnable)
    {
        var data = new Dictionary<string, object?>
        {
            ["username"] = "cerb_sennu_k7m2q6x4", ["audit_correlation_id"] = "audit",
            ["assignment_id"] = "assignment", ["managed_account_id"] = "account",
            ["membership_user_id"] = "member", ["marker_id"] = "marker"
        };
        if (intent is not null) data["enable_account"] = intent;
        var command = new AgentCommand("cmd", "windows.local_user.create", "idem", data);
        var method = typeof(LocalUserCommandHandlers).GetMethod("TryReadPayload", BindingFlags.NonPublic | BindingFlags.Static)!;
        object?[] arguments = [command, null, null];

        Assert.Equal(valid, Assert.IsType<bool>(method.Invoke(null, arguments)));
        if (valid)
        {
            var payload = arguments[1]!;
            Assert.Equal(expectedEnable, payload.GetType().GetProperty("EnableAccount")!.GetValue(payload));
            Assert.Equal(intent is bool, payload.GetType().GetProperty("EnableAccountExplicit")!.GetValue(payload));
        }
        else
        {
            Assert.Contains("invalid_payload", Convert.ToString(Assert.IsType<CommandResult>(arguments[2]).PostVerify));
        }
    }

    [Fact]
    public void IsAllowedUsername_AcceptsOnlyCurrentManagedShape()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("IsAllowedUsername", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        Assert.True(Assert.IsType<bool>(method.Invoke(null, ["cerb_sennu_k7m2q6x4"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, ["cerbtest_unit"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, ["sennurcop_k7m2q6x4aa"])));
    }

    [Fact]
    public void TryAcquireMutationSlot_RateLimitsDuplicateMutationForSameUser()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("TryAcquireMutationSlot", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var now = DateTimeOffset.UtcNow;
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        var suffixBytes = RandomNumberGenerator.GetBytes(8);
        var username = "cerb_ratea_" + new string(suffixBytes.Select(item => alphabet[item % alphabet.Length]).ToArray());
        var args = new object?[] { "create", username, now, null };

        Assert.True(Assert.IsType<bool>(method.Invoke(null, args)));

        args = ["create", username, now.AddMilliseconds(100), null];
        Assert.False(Assert.IsType<bool>(method.Invoke(null, args)));
        Assert.True(Assert.IsType<TimeSpan>(args[3]) > TimeSpan.Zero);

        args = ["disable", username, now.AddMilliseconds(100), null];
        Assert.True(Assert.IsType<bool>(method.Invoke(null, args)));
    }

    [Fact]
    public async Task RunLocalMutationAsync_RateLimitRefusalNeverInvokesActionAndBindsIdentifiers()
    {
        var runMethod = typeof(LocalUserCommandHandlers)
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Single(item => item.Name == "RunLocalMutationAsync" &&
                item.GetParameters().Length == 6 &&
                item.GetParameters()[1].ParameterType.IsGenericType &&
                item.GetParameters()[1].ParameterType.GetGenericTypeDefinition() == typeof(Func<,>));
        var slotMethod = typeof(LocalUserCommandHandlers)
            .GetMethod("TryAcquireMutationSlot", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(slotMethod);

        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        var suffixBytes = RandomNumberGenerator.GetBytes(8);
        var username = "cerb_rateb_" + new string(suffixBytes.Select(item => alphabet[item % alphabet.Length]).ToArray());
        var now = DateTimeOffset.UtcNow;
        var slotArguments = new object?[] { "create", username, now, null };
        Assert.True(Assert.IsType<bool>(slotMethod!.Invoke(null, slotArguments)));

        var payload = LocalUserPayload(
            username,
            "credential-profile-id",
            "tenant-key-id",
            "public-key",
            "aad");
        var payloadType = payload.GetType();
        var actionType = typeof(Func<,>).MakeGenericType(payloadType, typeof(CommandResult));
        var payloadParameter = Expression.Parameter(payloadType, "payload");
        var probeMethod = typeof(LocalUserCommandHandlersTests)
            .GetMethod(nameof(RateLimitProbe), BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(probeMethod);
        var action = Expression.Lambda(actionType, Expression.Call(probeMethod!), payloadParameter).Compile();
        Volatile.Write(ref _rateLimitProbeCalls, 0);

        var resultTask = Assert.IsType<Task<CommandResult>>(runMethod.Invoke(null,
            new object?[]
            {
                payload,
                action,
                "create",
                "test_failure",
                "must not execute",
                CancellationToken.None,
            }));
        var result = await resultTask;

        Assert.Equal(0, Volatile.Read(ref _rateLimitProbeCalls));
        Assert.Equal("FAILED", result.Status);
        var postVerify = JsonSerializer.SerializeToElement(result.PostVerify);
        Assert.Equal("local_user_rate_limited", postVerify.GetProperty("code").GetString());
        Assert.Equal("before_execution", postVerify.GetProperty("execution_stage").GetString());
        Assert.Equal("managed-account-id", postVerify.GetProperty("managed_account_id").GetString());
        Assert.Equal("assignment-id", postVerify.GetProperty("assignment_id").GetString());
        Assert.Equal("marker-id", postVerify.GetProperty("marker_id").GetString());
        Assert.Equal("credential-request-id", postVerify.GetProperty("credential_request_id").GetString());
    }

    [Fact]
    public void LocalMutationState_MapsOnlyProvenBoundariesToExecutionStages()
    {
        var stateType = typeof(LocalUserCommandHandlers)
            .GetNestedType("LocalMutationState", BindingFlags.NonPublic);
        Assert.NotNull(stateType);
        var stage = stateType!.GetProperty("ExecutionStage", BindingFlags.Public | BindingFlags.Instance);
        var markFirstWrite = stateType.GetMethod("MarkFirstWrite", BindingFlags.Public | BindingFlags.Instance);
        var markCommitted = stateType.GetMethod("MarkNativeMutationCommitted", BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(stage);
        Assert.NotNull(markFirstWrite);
        Assert.NotNull(markCommitted);

        static object CreateState(Type type)
            => Activator.CreateInstance(
                type,
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
                binder: null,
                args: null,
                culture: null)!;

        var before = CreateState(stateType);
        Assert.Equal("before_execution", stage!.GetValue(before));

        markFirstWrite!.Invoke(before, null);
        Assert.Equal("unknown", stage.GetValue(before));

        var committed = CreateState(stateType);
        markCommitted!.Invoke(committed, ["created"]);
        Assert.Equal("after_execution", stage.GetValue(committed));
        Assert.Equal("created", stateType.GetProperty("MutationResultCode")!.GetValue(committed));
        Assert.Equal("DONE", stateType.GetProperty("MutationResultStatus")!.GetValue(committed));
    }

    [Fact]
    public void ManagedUserCollision_BuilderBindsCodeAndBeforeExecutionStage()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("ManagedUserCollision", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var payload = LocalUserPayload(
            "cerb_sennu_k7m2q6x4",
            "credential-profile-id",
            "tenant-key-id",
            "public-key",
            "aad");

        var result = Assert.IsType<CommandResult>(method!.Invoke(null, [payload]));

        Assert.Equal("FAILED", result.Status);
        var postVerify = JsonSerializer.SerializeToElement(result.PostVerify);
        Assert.Equal("managed_user_collision", postVerify.GetProperty("code").GetString());
        Assert.Equal("before_execution", postVerify.GetProperty("execution_stage").GetString());
        Assert.Equal("managed-account-id", postVerify.GetProperty("managed_account_id").GetString());
        Assert.Equal("assignment-id", postVerify.GetProperty("assignment_id").GetString());
        Assert.Equal("marker-id", postVerify.GetProperty("marker_id").GetString());
        Assert.Equal("credential-request-id", postVerify.GetProperty("credential_request_id").GetString());
    }

    [Fact]
    public void IsDomainControllerProductType_OnlyMatchesLanmanNt()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("IsDomainControllerProductType", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);

        Assert.True(Assert.IsType<bool>(method.Invoke(null, ["LanmanNT"])));
        Assert.True(Assert.IsType<bool>(method.Invoke(null, ["lanmannt"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, ["ServerNT"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, ["WinNT"])));
        Assert.False(Assert.IsType<bool>(method.Invoke(null, [null])));
    }

    [Fact]
    public void EnsureLocalAccountsSupportedForProductType_FailsClosedOnDomainControllers()
    {
        var method = typeof(LocalUserCommandHandlers)
            .GetMethod("EnsureLocalAccountsSupportedForProductType", BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(method);
        var payload = LocalUserPayload(
            "cerb_sennu_k7m2q6x4",
            "credential-profile-id",
            "tenant-key-id",
            "public-key",
            "aad");

        var result = Assert.IsType<CommandResult>(method.Invoke(null, ["LanmanNT", payload]));

        Assert.Equal("FAILED", result.Status);
        Assert.Equal(2, result.ExitCode);
        Assert.Contains("domain controllers", result.Stderr);
        var postVerify = JsonSerializer.SerializeToElement(result.PostVerify);
        Assert.Equal("local_accounts_unsupported_on_domain_controller", postVerify.GetProperty("code").GetString());
        Assert.Equal("before_execution", postVerify.GetProperty("execution_stage").GetString());

        Assert.Null(method.Invoke(null, ["ServerNT", payload]));
        Assert.Null(method.Invoke(null, ["WinNT", payload]));
    }

    private static string PublicKeyPem(RSA rsa)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN PUBLIC KEY-----");
        builder.AppendLine(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END PUBLIC KEY-----");
        return builder.ToString();
    }

    private static string Sha256Hex(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();

    private static string Sha256HexAscii(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(value))).ToLowerInvariant();

    private static CommandResult RateLimitProbe()
    {
        Interlocked.Increment(ref _rateLimitProbeCalls);
        return new CommandResult("DONE", 0, null, null, new { code = "unexpected" });
    }

    private static object LocalUserPayload(
        string username,
        string credentialProfileId,
        string tenantKeyId,
        string publicPem,
        string aad)
    {
        var payloadType = typeof(LocalUserCommandHandlers)
            .GetNestedType("LocalUserPayload", BindingFlags.NonPublic);
        Assert.NotNull(payloadType);
        return Activator.CreateInstance(
            payloadType,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args:
            [
                username,
                "audit-id",
                "Sennur Copcu",
                "managed-account-id",
                "assignment-id",
                "membership-user-id",
                "marker-id",
                "credential-request-id",
                null,
                null,
                credentialProfileId,
                tenantKeyId,
                1,
                publicPem,
                Sha256HexAscii(publicPem),
                "aes256gcm+rsa-oaep",
                aad,
                Sha256Hex(aad),
                null,
            ],
            culture: null)!;
    }

    private static AgentCommand CreateCommand(string suffix)
        => new(
            $"cmd-{suffix}",
            "windows.local_user.create",
            $"idem-{suffix}",
            new
            {
                username = "cerb_sennu_k7m2q6x4",
                audit_correlation_id = "audit-id",
                managed_account_id = "managed-account-id",
                assignment_id = "assignment-id",
                membership_user_id = "membership-user-id",
                marker_id = "marker-id",
                credential_request_id = "credential-request-id",
            });

    private static ManagedAccountManifest FreshManifest(DateTimeOffset now)
    {
        const string canonical = "[{\"assignment_id\":\"assignment-id\",\"managed_account_id\":\"managed-account-id\",\"marker_id\":\"marker-id\",\"status\":\"active\",\"user_id\":\"membership-user-id\",\"username\":\"cerb_sennu_k7m2q6x4\"}]";
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        return new(
            hash[..16],
            hash,
            now.AddSeconds(300),
            true,
            [new("assignment-id", "managed-account-id", "membership-user-id", "cerb_sennu_k7m2q6x4", "marker-id", "active")]);
    }

    private static HeartbeatResponse ManifestHeartbeat(ManagedAccountManifest manifest)
        => JsonSerializer.Deserialize<HeartbeatResponse>("{}")! with
        {
            RequireManifestBeforeUnlock = true,
            ManifestVersion = manifest.Version,
            ManagedAccountManifestHash = manifest.Hash,
            ManifestFreshUntil = manifest.FreshUntil.ToString("O")
        };

    private sealed class NoopManifestReconciler : IManagedAccountReconciler
    {
        public Task ReconcileAsync(AgentIdentity identity, IReadOnlyList<ManagedAccountEntry> allowed, CancellationToken ct)
            => Task.CompletedTask;
    }
}
