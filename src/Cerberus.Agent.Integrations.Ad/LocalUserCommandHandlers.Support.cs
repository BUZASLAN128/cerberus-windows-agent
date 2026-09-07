using System.Collections;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Cerberus.Agent.Core;
using Microsoft.Win32;

namespace Cerberus.Agent.Integrations.Ad;

public static partial class LocalUserCommandHandlers
{
    private static CommandResult ManagedUserCollision(LocalUserPayload payload)
        => Fail(
            "managed_user_collision",
            "A local user with this managed username already exists but is not owned by Cerberus.",
            payload,
            executionStage: "before_execution");

    private static bool TryReadPayload(
        AgentCommand command,
        out LocalUserPayload payload,
        out CommandResult failure)
    {
        payload = new LocalUserPayload("", null, null);
        failure = Fail("invalid_payload", "Invalid local user command payload.", executionStage: "before_execution");

        if (!CommandPayload.TryDeserialize<LocalUserPayload>(command.Payload, out var parsed) || parsed is null)
            return false;

        var enableAccountExplicit = false;
        try
        {
            var raw = command.Payload is JsonElement element
                ? element
                : JsonSerializer.SerializeToElement(command.Payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            enableAccountExplicit = raw.ValueKind == JsonValueKind.Object &&
                raw.TryGetProperty("enable_account", out var enableAccount) &&
                enableAccount.ValueKind is JsonValueKind.True or JsonValueKind.False;
        }
        catch (Exception ex) when (ex is ArgumentException or JsonException)
        {
            _ = ex;
        }
        parsed = parsed with { EnableAccountExplicit = enableAccountExplicit };

        if (!IsAllowedUsername(parsed.Username))
        {
            failure = Fail(
                "invalid_username",
                "Local usernames must match the Cerberus managed-user format and fit Windows local account limits.",
                parsed,
                executionStage: "before_execution");
            return false;
        }

        if (string.IsNullOrWhiteSpace(parsed.AuditCorrelationId))
        {
            failure = Fail(
                "missing_audit_correlation",
                "Managed local user commands require an audit correlation id.",
                parsed,
                executionStage: "before_execution");
            return false;
        }

        if (
            ManagedUsernameRegex().IsMatch(parsed.Username) &&
            (
                string.IsNullOrWhiteSpace(parsed.MarkerId) ||
                string.IsNullOrWhiteSpace(parsed.ManagedAccountId) ||
                string.IsNullOrWhiteSpace(parsed.AssignmentId) ||
                string.IsNullOrWhiteSpace(parsed.MembershipUserId)
            )
        )
        {
            failure = Fail(
                "missing_managed_identity",
                "Managed local user commands require assignment, account, membership, and marker identity.",
                parsed,
                executionStage: "before_execution");
            return false;
        }

        if (!ValidateCredentialKey(parsed, out var keyFailure))
        {
            failure = keyFailure;
            return false;
        }

        if (!ValidateRdpCredentialKey(parsed, out var rdpKeyFailure))
        {
            failure = rdpKeyFailure;
            return false;
        }

        payload = parsed;
        return true;
    }

    private static bool IsAllowedUsername(string? username)
        => IsWindowsSafeUsername(username) &&
           ManagedUsernameRegex().IsMatch(username!);

    private static bool IsWindowsSafeUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return false;
        if (username.Length > MaxWindowsLocalUsernameLength)
            return false;
        if (username.EndsWith(".", StringComparison.Ordinal) || username.EndsWith(" ", StringComparison.Ordinal))
            return false;
        return !WindowsForbiddenUsernameCharsRegex().IsMatch(username);
    }

    private static DirectoryEntry OpenComputer()
        => new($"WinNT://{Environment.MachineName},computer");

    private static CommandResult? EnsureLocalAccountsSupported(LocalUserPayload payload)
        => EnsureLocalAccountsSupportedForProductType(ReadMachineProductType(), payload);

    private static CommandResult? EnsureLocalAccountsSupportedForProductType(string? productType, LocalUserPayload payload)
        => IsDomainControllerProductType(productType)
            ? Fail(
                "local_accounts_unsupported_on_domain_controller",
                UnsupportedDomainControllerMessage,
                payload,
                executionStage: "before_execution")
            : null;

    private static bool IsDomainController()
        => IsDomainControllerProductType(ReadMachineProductType());

    private static string? ReadMachineProductType()
        => Convert.ToString(Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions",
            "ProductType",
            null));

    private static bool IsDomainControllerProductType(string? productType)
        => string.Equals(productType, DomainControllerProductType, StringComparison.OrdinalIgnoreCase);

    private static bool TryFindUser(DirectoryEntry computer, string username, out DirectoryEntry? user)
    {
        try
        {
            user = computer.Children.Find(username, "user");
            return true;
        }
        catch (COMException)
        {
            user = null;
            return false;
        }
    }

    private static bool IsUserEnabled(string username)
    {
        using var computer = OpenComputer();
        if (!TryFindUser(computer, username, out var user) || user is null)
            return false;

        using (user)
        {
            return user.InvokeGet("AccountDisabled") is not true;
        }
    }

    private static string GeneratePassword() => RdpCredentialCodec.GeneratePassword();

    private static string ManagedDescription(LocalUserPayload payload)
        => ManagedUserDescription;

    private static void ApplyManagedPasswordPolicy(DirectoryEntry user, bool enableAccount = false)
    {
        var flags = Convert.ToInt32(user.Properties["UserFlags"].Value ?? 0);
        user.Properties["UserFlags"].Value = ApplyManagedPasswordPolicyFlags(flags, enableAccount);
    }

    private static int ApplyManagedPasswordPolicyFlags(int flags, bool enableAccount)
        // Only an explicit create intent may restore a disabled account after preparation.
        // Password rotation and manifest recovery alone preserve the disabled state.
        => (enableAccount ? flags & ~AccountDisabledFlag : flags) | PasswordCannotChangeFlag | PasswordNeverExpiresFlag;

    private static bool IsManagedByCerberus(DirectoryEntry user, LocalUserPayload payload, bool allowLegacy = false)
    {
        if (!ManagedUsernameRegex().IsMatch(payload.Username))
            return false;
        if (string.IsNullOrWhiteSpace(payload.MarkerId))
            return false;
        return payload.BoundIdentity is not null && RegistryManagedMarkerMatches(payload) &&
            RegistryOwnershipMatches(user, payload, allowLegacy);
    }

    private static string ManagedMarkerToken(string markerId)
        => $"{MarkerPrefix}{NormalizeMarkerId(markerId)};";

    private static string NormalizeMarkerId(string markerId)
        => markerId.StartsWith(MarkerPrefix, StringComparison.Ordinal)
            ? markerId[MarkerPrefix.Length..]
            : markerId;

    private static bool DescriptionManagedMarkerMatches(string description, string markerId)
    {
        if (description.Contains(ManagedMarkerToken(markerId), StringComparison.Ordinal))
            return true;

        var legacyToken = $"{MarkerPrefix}{markerId};";
        return !string.Equals(legacyToken, ManagedMarkerToken(markerId), StringComparison.Ordinal) &&
               description.Contains(legacyToken, StringComparison.Ordinal);
    }

    private static bool RegistryManagedMarkerMatches(LocalUserPayload payload)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ManagedUserRegistryPath(payload.Username));
            var marker = Convert.ToString(key?.GetValue("marker_id")) ?? string.Empty;
            return string.Equals(marker, NormalizeMarkerId(payload.MarkerId ?? string.Empty), StringComparison.Ordinal);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private static bool TryWriteManagedOwnership(
        LocalUserPayload payload,
        DirectoryEntry user,
        LocalMutationState? mutation = null)
    {
        try
        {
            var sid = GetLocalSid(user).Value;
            if (payload.BoundIdentity is null || string.IsNullOrWhiteSpace(sid)) return false;
            mutation?.MarkFirstWrite();
            using var key = Registry.LocalMachine.CreateSubKey(ManagedUserRegistryPath(payload.Username));
            if (key is null)
                return false;

            key.SetValue("marker_id", NormalizeMarkerId(payload.MarkerId ?? string.Empty), RegistryValueKind.String);
            key.SetValue("assignment_id", payload.AssignmentId ?? string.Empty, RegistryValueKind.String);
            key.SetValue("managed_account_id", payload.ManagedAccountId ?? string.Empty, RegistryValueKind.String);
            key.SetValue("membership_user_id", payload.MembershipUserId ?? string.Empty, RegistryValueKind.String);
            key.SetValue("agent_id", payload.BoundIdentity.AgentId, RegistryValueKind.String);
            key.SetValue("tenant_id", payload.BoundIdentity.TenantId, RegistryValueKind.String);
            key.SetValue("local_sid", sid, RegistryValueKind.String);
            return true;
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    private static void RemoveManagedOwnership(string username)
    {
        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(ManagedUserRegistryPath(username), throwOnMissingSubKey: false);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            _ = ex;
        }
    }

    private static string ManagedUserRegistryPath(string username)
        => $@"{ManagedUsersRegistryPath}\{username}";

    private static RdpLogonRightResult EnsureRemoteDesktopUserMembership(string username)
    {
        try
        {
            using var computer = OpenComputer();
            if (!TryFindUser(computer, username, out var user) || user is null)
                return new("failed", false);
            using (user)
            using (var group = OpenRemoteDesktopUsersGroup())
            {
                if (IsGroupMember(group, username))
                    return new("member", true);
                group.Invoke("Add", user.Path);
                return new("added", true);
            }
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new("failed", false);
        }
    }

    private static bool ShouldGrantRemoteDesktopMembership(
        bool existingUser,
        bool enableAccountExplicit,
        bool enableAccount)
        => !existingUser || (enableAccountExplicit && enableAccount);

    private static string RemoveRemoteDesktopUserMembership(string username)
    {
        try
        {
            using var computer = OpenComputer();
            if (!TryFindUser(computer, username, out var user) || user is null)
                return "not_member";
            using (user)
            using (var group = OpenRemoteDesktopUsersGroup())
            {
                if (!IsGroupMember(group, username))
                    return "not_member";
                group.Invoke("Remove", user.Path);
                return "removed";
            }
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidOperationException)
        {
            return "failed";
        }
    }

    private static DirectoryEntry OpenRemoteDesktopUsersGroup()
        => new($"WinNT://{Environment.MachineName}/{RemoteDesktopUsersGroupName()},group");

    private static string RemoteDesktopUsersGroupName()
    {
        try
        {
            var account = (NTAccount)new SecurityIdentifier(RemoteDesktopUsersSid).Translate(typeof(NTAccount));
            var value = account.Value;
            var slash = value.LastIndexOf('\\');
            return slash >= 0 ? value[(slash + 1)..] : value;
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException or ArgumentException)
        {
            return RemoteDesktopUsersFallbackName;
        }
    }

    private static bool IsGroupMember(DirectoryEntry group, string username)
    {
        var members = group.Invoke("Members");
        if (members is not IEnumerable enumerable)
            return false;

        foreach (var member in enumerable)
        {
            using var memberEntry = new DirectoryEntry(member);
            var memberName = Convert.ToString(memberEntry.Properties["Name"].Value);
            if (string.Equals(memberName, username, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static void TryRemoveUser(DirectoryEntry computer, string username)
    {
        try
        {
            if (TryFindUser(computer, username, out var user) && user is not null)
            {
                using (user)
                {
                    computer.Children.Remove(user);
                }
            }
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidOperationException)
        {
            _ = ex;
        }
    }

    private static SidLookupResult GetLocalSid(DirectoryEntry user)
    {
        try
        {
            if (user.Properties["objectSid"].Value is byte[] bytes && bytes.Length > 0)
                return new(new SecurityIdentifier(bytes, 0).Value, "ok");
        }
        catch (Exception ex) when (ex is InvalidOperationException or COMException or ArgumentException)
        {
            return new(null, ex.GetType().Name);
        }

        return new(null, "missing");
    }

    private static string? EncryptPassword(string password, LocalUserPayload payload)
    {
        if (string.IsNullOrWhiteSpace(payload.CredentialPublicKeyPem))
            return null;

        using var rsa = RSA.Create();
        rsa.ImportFromPem(payload.CredentialPublicKeyPem.AsSpan());
        var encrypted = rsa.Encrypt(
            Encoding.UTF8.GetBytes(password),
            RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(encrypted);
    }

    private static Dictionary<string, object?>? BuildRdpCredentialEnvelope(string password, LocalUserPayload payload)
        => string.IsNullOrWhiteSpace(payload.RdpPublicKeyPem) ? null :
            RdpCredentialCodec.Encrypt(password, payload.Username, payload.RdpDomain, RdpMetadata(payload)).AsDictionary();

    private static RdpCredentialMetadata RdpMetadata(LocalUserPayload payload) => new(
        payload.RdpCredentialProfileId, payload.RdpTenantKeyId, payload.RdpKeyVersion, payload.RdpPublicKeyPem,
        payload.RdpPublicKeyFingerprint, payload.RdpCipherAlg, payload.RdpAad, payload.RdpAadHash);

    private static bool ValidateCredentialKey(LocalUserPayload payload, out CommandResult failure)
    {
        failure = Fail(
            "invalid_credential_public_key",
            "Credential public key is invalid.",
            payload,
            executionStage: "before_execution");
        if (string.IsNullOrWhiteSpace(payload.CredentialPublicKeyPem))
            return true;

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(payload.CredentialPublicKeyPem.AsSpan());
            if (rsa.KeySize < MinCredentialKeySizeBits)
            {
                failure = Fail(
                    "weak_credential_public_key",
                    "Credential public key must be RSA 2048 bits or stronger.",
                    payload,
                    executionStage: "before_execution");
                return false;
            }

            if (string.IsNullOrWhiteSpace(payload.CredentialKeyFingerprint))
            {
                failure = Fail(
                    "missing_credential_public_key_fingerprint",
                    "Credential public key fingerprint is required.",
                    payload,
                    executionStage: "before_execution");
                return false;
            }

            if (!string.IsNullOrWhiteSpace(payload.CredentialKeyFingerprint))
            {
                var actual = Convert.ToHexString(
                    SHA256.HashData(Encoding.ASCII.GetBytes(payload.CredentialPublicKeyPem)))
                    .ToLowerInvariant();
                if (!string.Equals(actual, payload.CredentialKeyFingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    failure = Fail(
                        "credential_public_key_fingerprint_mismatch",
                        "Credential public key fingerprint does not match payload metadata.",
                        payload,
                        executionStage: "before_execution");
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            failure = Fail(
                "invalid_credential_public_key",
                "Credential public key could not be parsed.",
                payload,
                executionStage: "before_execution");
            return false;
        }
    }

    private static bool ValidateRdpCredentialKey(LocalUserPayload payload, out CommandResult failure)
    {
        var code = RdpCredentialCodec.ValidationError(RdpMetadata(payload));
        failure = Fail(code ?? "invalid_rdp_public_key", code switch
        {
            "missing_rdp_credential_metadata" => "RDP credential metadata is incomplete.",
            "unsupported_rdp_cipher" => "RDP credential cipher is unsupported.",
            "rdp_aad_hash_mismatch" => "RDP credential AAD hash does not match payload metadata.",
            "weak_rdp_public_key" => "RDP credential public key must be RSA 2048 bits or stronger.",
            "rdp_public_key_fingerprint_mismatch" => "RDP credential public key fingerprint does not match payload metadata.",
            _ => "RDP credential public key could not be parsed."
        }, payload, executionStage: "before_execution");
        return code is null;
    }

    private static CommandResult Success(
        string code,
        LocalUserPayload payload,
        bool enabled,
        string? localSid = null,
        string? encryptedPassword = null,
        Dictionary<string, object?>? rdpCredential = null,
        string? localSidStatus = null,
        string? rdpLogonRight = null)
        => new(
            "DONE",
            0,
            null,
            null,
            new
            {
                code,
                username = payload.Username,
                managed_account_id = payload.ManagedAccountId,
                assignment_id = payload.AssignmentId,
                marker_id = payload.MarkerId,
                credential_request_id = payload.CredentialRequestId,
                encrypted_password = encryptedPassword,
                encryption_key_fingerprint = payload.CredentialKeyFingerprint,
                rdp_credential = rdpCredential,
                local_sid = localSid,
                local_sid_status = localSidStatus ?? (localSid is null ? "unavailable" : "ok"),
                rdp_logon_right = rdpLogonRight,
                exists = code is not "deleted" and not "not_found",
                enabled,
            });

    private static bool TryAcquireMutationSlot(
        string mutationName,
        string username,
        DateTimeOffset now,
        out TimeSpan retryAfter)
    {
        retryAfter = TimeSpan.Zero;
        PruneMutationSlots(now);
        var key = $"{mutationName}:{username}";
        if (LastLocalMutationByKey.TryGetValue(key, out var last) && now - last < LocalMutationCooldown)
        {
            retryAfter = LocalMutationCooldown - (now - last);
            return false;
        }

        LastLocalMutationByKey[key] = now;
        return true;
    }

    private static void PruneMutationSlots(DateTimeOffset now)
    {
        foreach (var (key, value) in LastLocalMutationByKey)
        {
            if (now - value > TimeSpan.FromMinutes(5))
                LastLocalMutationByKey.TryRemove(key, out _);
        }
    }

    private static CommandResult Fail(
        string code,
        string message,
        LocalUserPayload? payload = null,
        string? rdpLogonRight = null,
        string executionStage = "unknown",
        string? mutationResultCode = null,
        string? mutationResultStatus = null,
        string? compensationStatus = null)
        => new(
            "FAILED",
            2,
            null,
            message,
            new
            {
                code,
                username = payload?.Username,
                managed_account_id = payload?.ManagedAccountId,
                assignment_id = payload?.AssignmentId,
                marker_id = payload?.MarkerId,
                credential_request_id = payload?.CredentialRequestId,
                rdp_logon_right = rdpLogonRight,
                execution_stage = executionStage,
                mutation_result_code = mutationResultCode,
                mutation_result_status = mutationResultStatus,
                compensation_status = compensationStatus,
            });

    // Managed Windows usernames use one canonical, Windows-safe shape:
    // cerb_<5 lower alnum chars starting with a letter>_<8 lower base32 chars>.
    [GeneratedRegex("^cerb_[a-z][a-z0-9]{4}_[a-z2-7]{8}$", RegexOptions.CultureInvariant)]
    private static partial Regex ManagedUsernameRegex();

    [GeneratedRegex("[\"/\\\\\\[\\]:;|=,+*?<>@]", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsForbiddenUsernameCharsRegex();

    private sealed record LocalUserPayload(
        [property: JsonPropertyName("username")] string Username,
        [property: JsonPropertyName("audit_correlation_id")] string? AuditCorrelationId,
        [property: JsonPropertyName("display_name")] string? DisplayName,
        [property: JsonPropertyName("managed_account_id")] string? ManagedAccountId = null,
        [property: JsonPropertyName("assignment_id")] string? AssignmentId = null,
        [property: JsonPropertyName("membership_user_id")] string? MembershipUserId = null,
        [property: JsonPropertyName("marker_id")] string? MarkerId = null,
        [property: JsonPropertyName("credential_request_id")] string? CredentialRequestId = null,
        [property: JsonPropertyName("credential_public_key_pem")] string? CredentialPublicKeyPem = null,
        [property: JsonPropertyName("credential_key_fingerprint")] string? CredentialKeyFingerprint = null,
        [property: JsonPropertyName("rdp_credential_profile_id")] string? RdpCredentialProfileId = null,
        [property: JsonPropertyName("rdp_tenant_key_id")] string? RdpTenantKeyId = null,
        [property: JsonPropertyName("rdp_key_version")] int? RdpKeyVersion = null,
        [property: JsonPropertyName("rdp_public_key_pem")] string? RdpPublicKeyPem = null,
        [property: JsonPropertyName("rdp_public_key_fingerprint")] string? RdpPublicKeyFingerprint = null,
        [property: JsonPropertyName("rdp_cipher_alg")] string? RdpCipherAlg = null,
        [property: JsonPropertyName("rdp_aad")] string? RdpAad = null,
        [property: JsonPropertyName("rdp_aad_hash")] string? RdpAadHash = null,
        [property: JsonPropertyName("rdp_domain")] string? RdpDomain = null)
    {
        [JsonPropertyName("enable_account")] public bool EnableAccount { get; init; }
        [JsonIgnore] public bool EnableAccountExplicit { get; init; }
        [JsonIgnore] public AgentIdentity? BoundIdentity { get; init; }
    }

    private sealed record RdpLogonRightResult(string Status, bool Granted);
    private sealed record SidLookupResult(string? Value, string Status);
}
