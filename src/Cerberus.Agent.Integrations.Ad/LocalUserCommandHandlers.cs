using System.DirectoryServices;
using System.Collections;
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
    private const string MarkerPrefix = "cerberus-managed-local-user:";
    private const int MaxWindowsLocalUsernameLength = 20;
    private const int MinCredentialKeySizeBits = 2048;
    private const string PasswordLower = "abcdefghijkmnopqrstuvwxyz";
    private const string PasswordUpper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string PasswordDigits = "23456789";
    private const string PasswordSymbols = "!@#$%^*-_+=";
    private const string PasswordAll = PasswordLower + PasswordUpper + PasswordDigits + PasswordSymbols;
    private const string RdpCredentialCipherAlg = "aes256gcm+rsa-oaep";
    private const int RdpCredentialDekBytes = 32;
    private const int RdpCredentialNonceBytes = 12;
    private const int RdpCredentialTagBytes = 16;
    private const string DomainControllerProductType = "LanmanNT";
    private const string UnsupportedDomainControllerMessage = "Local account commands are not supported on domain controllers.";
    private const string CreateFailedMessage = "Local user create operation failed.";
    private const string DisableFailedMessage = "Local user disable operation failed.";
    private const string DeleteFailedMessage = "Local user delete operation failed.";
    private const string RemoteDesktopUsersSid = "S-1-5-32-555";
    private const string RemoteDesktopUsersFallbackName = "Remote Desktop Users";
    private const string ManagedUsersRegistryPath = @"SOFTWARE\Cerberus\ManagedLocalUsers";
    private const string ManagedUserDescription = "Cerberus managed local account.";
    private const int PasswordCannotChangeFlag = 0x0040;
    private const int PasswordNeverExpiresFlag = 0x10000;

    public static ICommandHandler[] CreateDefaultHandlers()
        =>
        [
            new CreateManagedUser(),
            new DisableManagedUser(),
            new DeleteManagedUser(),
        ];

    private sealed class CreateManagedUser : ICommandHandler
    {
        public string Type => "windows.local_user.create";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            if (!TryReadPayload(command, out var payload, out var failure))
                return Task.FromResult(failure);

            return RunLocalMutationAsync(
                payload,
                CreateOrRotateUser,
                "local_user_create_failed",
                CreateFailedMessage,
                ct);
        }
    }

    private sealed class DisableManagedUser : ICommandHandler
    {
        public string Type => "windows.local_user.disable";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            if (!TryReadPayload(command, out var payload, out var failure))
                return Task.FromResult(failure);

            return RunLocalMutationAsync(
                payload,
                DisableUser,
                "local_user_disable_failed",
                DisableFailedMessage,
                ct);
        }
    }

    private sealed class DeleteManagedUser : ICommandHandler
    {
        public string Type => "windows.local_user.delete";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            if (!TryReadPayload(command, out var payload, out var failure))
                return Task.FromResult(failure);

            return RunLocalMutationAsync(
                payload,
                DeleteUser,
                "local_user_delete_failed",
                DeleteFailedMessage,
                ct);
        }
    }

    private static Task<CommandResult> RunLocalMutationAsync(
        LocalUserPayload payload,
        Func<LocalUserPayload, CommandResult> action,
        string failureCode,
        string failureMessage,
        CancellationToken ct)
        => Task.Run(
            () =>
            {
                ct.ThrowIfCancellationRequested();
                var unsupported = EnsureLocalAccountsSupported(payload);
                if (unsupported is not null)
                    return unsupported;

                try
                {
                    return action(payload);
                }
                catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidOperationException)
                {
                    _ = ex;
                    return Fail(failureCode, failureMessage, payload);
                }
            },
            ct);

    private static CommandResult CreateOrRotateUser(LocalUserPayload payload)
    {
        using var computer = OpenComputer();
        if (TryFindUser(computer, payload.Username, out var existing))
        {
            if (existing is null)
                return Fail("local_user_lookup_failed", "Local user lookup returned no entry.", payload);

            using (existing)
            {
                if (!IsManagedByCerberus(existing, payload))
                    return ManagedUserCollision(payload);

                if (!TryWriteManagedOwnership(payload))
                    return Fail("managed_ownership_write_failed", "Managed user ownership marker could not be persisted.", payload);

                var rdpLogonRight = EnsureRemoteDesktopUserMembership(payload.Username);
                if (!rdpLogonRight.Granted)
                    return Fail("rdp_logon_right_failed", "Remote Desktop Users membership could not be granted.", payload, rdpLogonRight.Status);

                var password = GeneratePassword();
                existing.Invoke("SetPassword", password);
                existing.Properties["Description"].Value = ManagedDescription(payload);
                ApplyManagedPasswordPolicy(existing);
                existing.CommitChanges();
                return Success(
                    payload.CredentialRequestId is null ? "already_exists" : "password_rotated",
                    payload,
                    enabled: IsUserEnabled(payload.Username),
                    localSid: GetLocalSid(existing),
                    encryptedPassword: EncryptPassword(password, payload),
                    rdpCredential: BuildRdpCredentialEnvelope(password, payload),
                    rdpLogonRight: rdpLogonRight.Status);
            }
        }

        using var user = computer.Children.Add(payload.Username, "user");
        var generatedPassword = GeneratePassword();
        user.Invoke("SetPassword", generatedPassword);
        user.Properties["FullName"].Value = payload.DisplayName ?? "Cerberus managed user";
        user.Properties["Description"].Value = ManagedDescription(payload);
        ApplyManagedPasswordPolicy(user);
        user.CommitChanges();
        if (!TryWriteManagedOwnership(payload))
        {
            TryRemoveUser(computer, payload.Username);
            return Fail("managed_ownership_write_failed", "Managed user ownership marker could not be persisted.", payload);
        }

        var createdRdpLogonRight = EnsureRemoteDesktopUserMembership(payload.Username);
        if (!createdRdpLogonRight.Granted)
        {
            RemoveManagedOwnership(payload.Username);
            TryRemoveUser(computer, payload.Username);
            return Fail("rdp_logon_right_failed", "Remote Desktop Users membership could not be granted.", payload, createdRdpLogonRight.Status);
        }

        return Success(
            "created",
            payload,
            enabled: true,
            localSid: GetLocalSid(user),
            encryptedPassword: EncryptPassword(generatedPassword, payload),
            rdpCredential: BuildRdpCredentialEnvelope(generatedPassword, payload),
            rdpLogonRight: createdRdpLogonRight.Status);
    }

    private static CommandResult DisableUser(LocalUserPayload payload)
    {
        using var computer = OpenComputer();
        if (!TryFindUser(computer, payload.Username, out var user) || user is null)
            return Success("not_found", payload, enabled: false);

        using (user)
        {
            if (!IsManagedByCerberus(user, payload))
                return ManagedUserCollision(payload);

            var rdpLogonRight = RemoveRemoteDesktopUserMembership(payload.Username);
            user.InvokeSet("AccountDisabled", true);
            user.CommitChanges();
            return Success(
                "disabled",
                payload,
                enabled: false,
                localSid: GetLocalSid(user),
                rdpLogonRight: rdpLogonRight);
        }
    }

    private static CommandResult DeleteUser(LocalUserPayload payload)
    {
        using var computer = OpenComputer();
        if (!TryFindUser(computer, payload.Username, out var user) || user is null)
            return Success("not_found", payload, enabled: false);

        using (user)
        {
            if (!IsManagedByCerberus(user, payload))
                return ManagedUserCollision(payload);

            var sid = GetLocalSid(user);
            var rdpLogonRight = RemoveRemoteDesktopUserMembership(payload.Username);
            computer.Children.Remove(user);
            RemoveManagedOwnership(payload.Username);
            return Success(
                "deleted",
                payload,
                enabled: false,
                localSid: sid,
                rdpLogonRight: rdpLogonRight);
        }
    }

    private static CommandResult ManagedUserCollision(LocalUserPayload payload)
        => Fail(
            "managed_user_collision",
            "A local user with this managed username already exists but is not owned by Cerberus.",
            payload);

    private static bool TryReadPayload(
        AgentCommand command,
        out LocalUserPayload payload,
        out CommandResult failure)
    {
        payload = new LocalUserPayload("", null, null);
        failure = Fail("invalid_payload", "Invalid local user command payload.");

        if (!CommandPayload.TryDeserialize<LocalUserPayload>(command.Payload, out var parsed) || parsed is null)
            return false;

        if (!IsAllowedUsername(parsed.Username))
        {
            failure = Fail("invalid_username", "Local usernames must match the Cerberus managed-user format and fit Windows local account limits.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(parsed.AuditCorrelationId))
        {
            failure = Fail("missing_audit_correlation", "Managed local user commands require an audit correlation id.");
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
                parsed);
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
        => IsDomainController()
            ? Fail("local_accounts_unsupported_on_domain_controller", UnsupportedDomainControllerMessage, payload)
            : null;

    private static bool IsDomainController()
        => IsDomainControllerProductType(Convert.ToString(Registry.GetValue(
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions",
            "ProductType",
            null)));

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

    private static string GeneratePassword()
    {
        Span<char> chars = stackalloc char[28];
        chars[0] = Pick(PasswordLower);
        chars[1] = Pick(PasswordUpper);
        chars[2] = Pick(PasswordDigits);
        chars[3] = Pick(PasswordSymbols);
        for (var i = 4; i < chars.Length; i++)
            chars[i] = Pick(PasswordAll);

        for (var i = chars.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }

        return new string(chars);
    }

    private static string ManagedDescription(LocalUserPayload payload)
        => ManagedUserDescription;

    private static void ApplyManagedPasswordPolicy(DirectoryEntry user)
    {
        var flags = Convert.ToInt32(user.Properties["UserFlags"].Value ?? 0);
        user.Properties["UserFlags"].Value = ApplyManagedPasswordPolicyFlags(flags);
    }

    private static int ApplyManagedPasswordPolicyFlags(int flags)
        => flags | PasswordCannotChangeFlag | PasswordNeverExpiresFlag;

    private static bool IsManagedByCerberus(DirectoryEntry user, LocalUserPayload payload)
    {
        if (!ManagedUsernameRegex().IsMatch(payload.Username))
            return false;
        if (string.IsNullOrWhiteSpace(payload.MarkerId))
            return false;
        if (RegistryManagedMarkerMatches(payload))
            return true;

        var description = Convert.ToString(user.Properties["Description"].Value) ?? string.Empty;
        return DescriptionManagedMarkerMatches(description, payload.MarkerId);
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

    private static bool TryWriteManagedOwnership(LocalUserPayload payload)
    {
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(ManagedUserRegistryPath(payload.Username));
            if (key is null)
                return false;

            key.SetValue("marker_id", NormalizeMarkerId(payload.MarkerId ?? string.Empty), RegistryValueKind.String);
            key.SetValue("assignment_id", payload.AssignmentId ?? string.Empty, RegistryValueKind.String);
            key.SetValue("managed_account_id", payload.ManagedAccountId ?? string.Empty, RegistryValueKind.String);
            key.SetValue("membership_user_id", payload.MembershipUserId ?? string.Empty, RegistryValueKind.String);
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

    private static string? GetLocalSid(DirectoryEntry user)
    {
        try
        {
            if (user.Properties["objectSid"].Value is byte[] bytes && bytes.Length > 0)
                return new SecurityIdentifier(bytes, 0).Value;
        }
        catch (Exception ex) when (ex is InvalidOperationException or COMException or ArgumentException)
        {
            return null;
        }

        return null;
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
    {
        if (string.IsNullOrWhiteSpace(payload.RdpPublicKeyPem))
            return null;

        if (string.IsNullOrWhiteSpace(payload.RdpCredentialProfileId) ||
            string.IsNullOrWhiteSpace(payload.RdpTenantKeyId) ||
            payload.RdpKeyVersion is null ||
            string.IsNullOrWhiteSpace(payload.RdpAad) ||
            string.IsNullOrWhiteSpace(payload.RdpAadHash))
        {
            throw new InvalidOperationException("RDP credential metadata is incomplete.");
        }

        using var plaintext = new MemoryStream();
        using (var writer = new Utf8JsonWriter(plaintext))
        {
            writer.WriteStartObject();
            writer.WriteString("username", payload.Username);
            writer.WriteString("password", password);
            if (!string.IsNullOrWhiteSpace(payload.RdpDomain))
                writer.WriteString("domain", payload.RdpDomain);
            writer.WriteEndObject();
        }
        var aad = Encoding.UTF8.GetBytes(payload.RdpAad);
        var dek = RandomNumberGenerator.GetBytes(RdpCredentialDekBytes);
        var nonce = RandomNumberGenerator.GetBytes(RdpCredentialNonceBytes);
        var plaintextSpan = plaintext.GetBuffer().AsSpan(0, checked((int)plaintext.Length));
        var ciphertext = new byte[plaintextSpan.Length];
        var tag = new byte[RdpCredentialTagBytes];

        try
        {
            using (var aes = new AesGcm(dek, RdpCredentialTagBytes))
            {
                aes.Encrypt(nonce, plaintextSpan, ciphertext, tag, aad);
            }

            var cipherWithTag = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, cipherWithTag, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, cipherWithTag, ciphertext.Length, tag.Length);

            using var rsa = RSA.Create();
            rsa.ImportFromPem(payload.RdpPublicKeyPem.AsSpan());
            var wrappedDek = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);

            return new Dictionary<string, object?>
            {
                ["auth_type"] = "password",
                ["credential_id"] = payload.RdpCredentialProfileId,
                ["username_hint"] = payload.Username,
                ["domain"] = string.IsNullOrWhiteSpace(payload.RdpDomain) ? null : payload.RdpDomain,
                ["tenant_key_id"] = payload.RdpTenantKeyId,
                ["key_version"] = payload.RdpKeyVersion,
                ["cipher_alg"] = RdpCredentialCipherAlg,
                ["wrapped_dek"] = Convert.ToBase64String(wrappedDek),
                ["cipher_nonce"] = Convert.ToBase64String(nonce),
                ["ciphertext"] = Convert.ToBase64String(cipherWithTag),
                ["aad_hash"] = payload.RdpAadHash,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(plaintext.GetBuffer().AsSpan(0, checked((int)plaintext.Length)));
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static bool ValidateCredentialKey(LocalUserPayload payload, out CommandResult failure)
    {
        failure = Fail("invalid_credential_public_key", "Credential public key is invalid.", payload);
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
                    payload);
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
                        payload);
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            failure = Fail("invalid_credential_public_key", "Credential public key could not be parsed.", payload);
            return false;
        }
    }

    private static bool ValidateRdpCredentialKey(LocalUserPayload payload, out CommandResult failure)
    {
        failure = Fail("invalid_rdp_public_key", "RDP credential public key is invalid.", payload);
        if (string.IsNullOrWhiteSpace(payload.RdpPublicKeyPem))
            return true;

        if (string.IsNullOrWhiteSpace(payload.RdpCredentialProfileId) ||
            string.IsNullOrWhiteSpace(payload.RdpTenantKeyId) ||
            payload.RdpKeyVersion is null ||
            string.IsNullOrWhiteSpace(payload.RdpAad) ||
            string.IsNullOrWhiteSpace(payload.RdpAadHash))
        {
            failure = Fail("missing_rdp_credential_metadata", "RDP credential metadata is incomplete.", payload);
            return false;
        }

        if (!string.Equals(payload.RdpCipherAlg, RdpCredentialCipherAlg, StringComparison.Ordinal))
        {
            failure = Fail("unsupported_rdp_cipher", "RDP credential cipher is unsupported.", payload);
            return false;
        }

        var actualAadHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(payload.RdpAad)))
            .ToLowerInvariant();
        if (!string.Equals(actualAadHash, payload.RdpAadHash, StringComparison.OrdinalIgnoreCase))
        {
            failure = Fail("rdp_aad_hash_mismatch", "RDP credential AAD hash does not match payload metadata.", payload);
            return false;
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(payload.RdpPublicKeyPem.AsSpan());
            if (rsa.KeySize < MinCredentialKeySizeBits)
            {
                failure = Fail(
                    "weak_rdp_public_key",
                    "RDP credential public key must be RSA 2048 bits or stronger.",
                    payload);
                return false;
            }

            if (!string.IsNullOrWhiteSpace(payload.RdpPublicKeyFingerprint))
            {
                var actual = Convert.ToHexString(
                    SHA256.HashData(Encoding.ASCII.GetBytes(payload.RdpPublicKeyPem)))
                    .ToLowerInvariant();
                if (!string.Equals(actual, payload.RdpPublicKeyFingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    failure = Fail(
                        "rdp_public_key_fingerprint_mismatch",
                        "RDP credential public key fingerprint does not match payload metadata.",
                        payload);
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            failure = Fail("invalid_rdp_public_key", "RDP credential public key could not be parsed.", payload);
            return false;
        }
    }

    private static char Pick(string alphabet) => alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];

    private static CommandResult Success(
        string code,
        LocalUserPayload payload,
        bool enabled,
        string? localSid = null,
        string? encryptedPassword = null,
        Dictionary<string, object?>? rdpCredential = null,
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
                local_sid_status = localSid is null ? "unavailable" : "ok",
                rdp_logon_right = rdpLogonRight,
                exists = code is not "deleted" and not "not_found",
                enabled,
            });

    private static CommandResult Fail(string code, string message, LocalUserPayload? payload = null, string? rdpLogonRight = null)
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
            });

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
        [property: JsonPropertyName("rdp_domain")] string? RdpDomain = null);

    private sealed record RdpLogonRightResult(string Status, bool Granted);
}
