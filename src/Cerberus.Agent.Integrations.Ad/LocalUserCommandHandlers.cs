using System.DirectoryServices;
using System.Collections;
using System.Collections.Concurrent;
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
    private static readonly TimeSpan LocalMutationCooldown = TimeSpan.FromSeconds(2);
    private static readonly ConcurrentDictionary<string, DateTimeOffset> LastLocalMutationByKey = new(StringComparer.OrdinalIgnoreCase);

    public static ICommandHandler[] CreateDefaultHandlers(LocalUserCommandPolicy? policy = null)
    {
        policy ??= LocalUserCommandPolicy.CreateDisabled;
        return
        [
            new CreateManagedUser(policy),
            new DisableManagedUser(),
            new DeleteManagedUser(),
        ];
    }

    private sealed class CreateManagedUser : ICommandHandler
    {
        private readonly LocalUserCommandPolicy _policy;

        public CreateManagedUser(LocalUserCommandPolicy policy)
        {
            _policy = policy;
        }

        public string Type => "windows.local_user.create";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            if (!_policy.CreateEnabled)
            {
                return Task.FromResult(Fail(
                    "local_user_create_disabled_by_policy",
                    "Managed local user create is disabled by local agent policy."));
            }

            if (!TryReadPayload(command, out var payload, out var failure))
                return Task.FromResult(failure);

            return RunLocalMutationAsync(
                payload,
                CreateOrRotateUser,
                "create",
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
                "disable",
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
                "delete",
                "local_user_delete_failed",
                DeleteFailedMessage,
                ct);
        }
    }

    private static Task<CommandResult> RunLocalMutationAsync(
        LocalUserPayload payload,
        Func<LocalUserPayload, CommandResult> action,
        string mutationName,
        string failureCode,
        string failureMessage,
        CancellationToken ct)
        => Task.Run(
            () =>
            {
                ct.ThrowIfCancellationRequested();
                if (!TryAcquireMutationSlot(mutationName, payload.Username, DateTimeOffset.UtcNow, out var retryAfter))
                {
                    return Fail(
                        "local_user_rate_limited",
                        $"Managed local user {mutationName} is rate limited. Retry after {retryAfter.TotalSeconds:F0} seconds.",
                        payload);
                }

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
                var localSid = GetLocalSid(existing);
                return Success(
                    payload.CredentialRequestId is null ? "already_exists" : "password_rotated",
                    payload,
                    enabled: IsUserEnabled(payload.Username),
                    localSid: localSid.Value,
                    localSidStatus: localSid.Status,
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

        var createdSid = GetLocalSid(user);
        return Success(
            "created",
            payload,
            enabled: true,
            localSid: createdSid.Value,
            localSidStatus: createdSid.Status,
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
            var localSid = GetLocalSid(user);
            return Success(
                "disabled",
                payload,
                enabled: false,
                localSid: localSid.Value,
                localSidStatus: localSid.Status,
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
                localSid: sid.Value,
                localSidStatus: sid.Status,
                rdpLogonRight: rdpLogonRight);
        }
    }

}
