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
    private const string DomainControllerProductType = "LanmanNT";
    private const string UnsupportedDomainControllerMessage = "Local account commands are not supported on domain controllers.";
    private const string CreateFailedMessage = "Local user create operation failed.";
    private const string DisableFailedMessage = "Local user disable operation failed.";
    private const string DeleteFailedMessage = "Local user delete operation failed.";
    private const string RemoteDesktopUsersSid = "S-1-5-32-555";
    private const string RemoteDesktopUsersFallbackName = "Remote Desktop Users";
    private const string ManagedUsersRegistryPath = @"SOFTWARE\Cerberus\ManagedLocalUsers";
    private const string ManagedUserDescription = "Cerberus managed local account.";
    private const int AccountDisabledFlag = 0x0002;
    private const int PasswordCannotChangeFlag = 0x0040;
    private const int PasswordNeverExpiresFlag = 0x10000;
    private static readonly TimeSpan LocalMutationCooldown = TimeSpan.FromSeconds(2);
    private static readonly ConcurrentDictionary<string, DateTimeOffset> LastLocalMutationByKey = new(StringComparer.OrdinalIgnoreCase);

    private enum LocalMutationPhase
    {
        BeforeExecution,
        FirstWriteStarted,
        NativeMutationCommitted,
    }

    private sealed class LocalMutationState
    {
        public LocalMutationPhase Phase { get; private set; }
        public string? MutationResultCode { get; private set; }
        public string? MutationResultStatus { get; private set; }

        public string ExecutionStage => Phase switch
        {
            LocalMutationPhase.BeforeExecution => "before_execution",
            LocalMutationPhase.NativeMutationCommitted => "after_execution",
            _ => "unknown",
        };

        public void MarkFirstWrite()
        {
            if (Phase == LocalMutationPhase.BeforeExecution)
                Phase = LocalMutationPhase.FirstWriteStarted;
        }

        public void MarkNativeMutationCommitted(string resultCode)
        {
            Phase = LocalMutationPhase.NativeMutationCommitted;
            MutationResultCode = resultCode;
            MutationResultStatus = "DONE";
        }
    }

    public static ICommandHandler[] CreateDefaultHandlers(LocalUserCommandPolicy? policy = null,
        ManagedAccountManifestPolicy? manifest = null,
        Func<LocalUserCommandPolicy>? policyResolver = null)
    {
        var resolver = policyResolver ?? (policy is null
            ? LocalUserCommandPolicy.Resolve
            : () => policy);
        return
        [
            new CreateManagedUser(resolver, manifest),
            new DisableManagedUser(manifest?.Identity),
            new DeleteManagedUser(manifest?.Identity),
        ];
    }

    private sealed class CreateManagedUser : ICommandHandler, ICommandExecutionGate, IReplayAwareCommandExecutionGate
    {
        private readonly Func<LocalUserCommandPolicy> _policyResolver;
        private readonly ManagedAccountManifestPolicy? _manifest;

        public CreateManagedUser(Func<LocalUserCommandPolicy> policyResolver, ManagedAccountManifestPolicy? manifest)
        {
            _policyResolver = policyResolver;
            _manifest = manifest;
        }

        public string Type => "windows.local_user.create";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
            => ExecuteAuthorizedAsync(command, () => HandleAuthorizedAsync(command, ct), ct);

        public Task<CommandResult> ExecuteAuthorizedAsync(AgentCommand command, Func<Task<CommandResult>> execute, CancellationToken ct)
            => ExecuteAuthorizedAsync(command, cachedResult: null, execute: execute, ct: ct);

        public async Task<CommandResult> ExecuteAuthorizedAsync(
            AgentCommand command,
            CommandResult? cachedResult,
            Func<Task<CommandResult>> execute,
            CancellationToken ct)
        {
            if (!TryReadPayload(command, out var payload, out var failure))
                return failure;

            // Fresh policy denial must retain the request identifiers for backend
            // reconciliation; a cached replay skips only this local approval half.
            if (cachedResult is null)
            {
                var policyFailure = CreatePolicyFailure(_policyResolver, payload);
                if (policyFailure is not null)
                    return policyFailure;
            }

            if (_manifest is null)
                return BindManifestFailure(payload, ManagedAccountManifestPolicy.Denied(
                    ToManagedAccountEntry(payload), "before_execution"), cachedResult);
            payload = payload with { BoundIdentity = _manifest.Identity };
            try
            {
                var result = await _manifest.ExecuteAuthorizedAsync(
                    ToManagedAccountEntry(payload),
                    payload.EnableAccount,
                    payload.EnableAccountExplicit,
                    () => cachedResult is null ? execute() : Task.FromResult(cachedResult),
                    ct).ConfigureAwait(false);
                return BindManifestFailure(payload, result, cachedResult);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                _ = ex;
                return Fail(
                    "managed_account_manifest_required",
                    "Fresh managed account manifest authority is required.",
                    payload,
                    executionStage: "unknown");
            }
        }

        public Task<CommandResult> HandleAuthorizedAsync(AgentCommand command, CancellationToken ct)
        {
            if (!TryReadPayload(command, out var payload, out var failure)) return Task.FromResult(failure);
            var policyFailure = CreatePolicyFailure(_policyResolver, payload);
            if (policyFailure is not null) return Task.FromResult(policyFailure);
            if (_manifest is null)
                return Task.FromResult(BindManifestFailure(payload, ManagedAccountManifestPolicy.Denied(
                    ToManagedAccountEntry(payload), "before_execution")));
            payload = payload with { BoundIdentity = _manifest.Identity };

            return RunLocalMutationAsync(
                payload,
                (item, mutation) => CreateOrRotateUser(item, _policyResolver, mutation),
                "create",
                "local_user_create_failed",
                CreateFailedMessage,
                ct);
        }
    }

    private sealed class DisableManagedUser(AgentIdentity? identity) : ICommandHandler
    {
        public string Type => "windows.local_user.disable";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            if (!TryReadPayload(command, out var payload, out var failure))
                return Task.FromResult(failure);

            payload = payload with { BoundIdentity = identity };

            return RunLocalMutationAsync(
                payload,
                DisableUser,
                "disable",
                "local_user_disable_failed",
                DisableFailedMessage,
                ct);
        }
    }

    private sealed class DeleteManagedUser(AgentIdentity? identity) : ICommandHandler
    {
        public string Type => "windows.local_user.delete";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            if (!TryReadPayload(command, out var payload, out var failure))
                return Task.FromResult(failure);

            payload = payload with { BoundIdentity = identity };

            return RunLocalMutationAsync(
                payload,
                DeleteUser,
                "delete",
                "local_user_delete_failed",
                DeleteFailedMessage,
                ct);
        }
    }

    private static CommandResult? CreatePolicyFailure(
        Func<LocalUserCommandPolicy> policyResolver,
        LocalUserPayload? payload = null)
    {
        LocalUserCommandPolicy policy;
        try
        {
            policy = policyResolver();
        }
        catch (Exception)
        {
            return Fail(
                "local_user_create_policy_unknown",
                "Managed local user create is disabled because local agent policy is unavailable.",
                payload,
                executionStage: "before_execution");
        }

        if (policy.CreateEnabled)
            return null;

        return policy.State == LocalUserCreatePolicyState.Unknown
            ? Fail(
                "local_user_create_policy_unknown",
                "Managed local user create is disabled because local agent policy is unavailable.",
                payload,
                executionStage: "before_execution")
            : Fail(
                "local_user_create_disabled_by_policy",
                "Managed local user create is disabled by local agent policy.",
                payload,
                executionStage: "before_execution");
    }

    private static ManagedAccountEntry ToManagedAccountEntry(LocalUserPayload payload)
        => new(payload.AssignmentId!, payload.ManagedAccountId!, payload.MembershipUserId!, payload.Username,
            payload.MarkerId!, "active");

    private static CommandResult BindManifestFailure(
        LocalUserPayload payload, CommandResult result, CommandResult? priorResult = null)
    {
        if (!string.Equals(ReadPostVerifyString(result.PostVerify, "code"),
                "managed_account_manifest_required", StringComparison.Ordinal))
            return result;

        return Fail(
            "managed_account_manifest_required",
            result.Stderr ?? "Fresh managed account manifest authority is required.",
            payload,
            executionStage: ReadPostVerifyString(result.PostVerify, "execution_stage") ?? "unknown",
            mutationResultCode: ReadPostVerifyString(result.PostVerify, "mutation_result_code") ??
                ReadPostVerifyString(priorResult?.PostVerify, "code"),
            mutationResultStatus: ReadPostVerifyString(result.PostVerify, "mutation_result_status") ??
                priorResult?.Status,
            compensationStatus: ReadPostVerifyString(result.PostVerify, "compensation_status"));
    }

    private static string? ReadPostVerifyString(object? postVerify, string name)
    {
        if (postVerify is null) return null;
        if (postVerify is JsonElement element && element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(name, out var property))
            return property.ValueKind == JsonValueKind.String ? property.GetString() : property.ToString();
        if (postVerify is IDictionary dictionary && dictionary.Contains(name))
            return Convert.ToString(dictionary[name]);
        return postVerify.GetType().GetProperty(name)?.GetValue(postVerify)?.ToString();
    }

    private static Task<CommandResult> RunLocalMutationAsync(
        LocalUserPayload payload,
        Func<LocalUserPayload, CommandResult> action,
        string mutationName,
        string failureCode,
        string failureMessage,
        CancellationToken ct)
        => RunLocalMutationAsync(
            payload,
            (_, _) => action(payload),
            mutationName,
            failureCode,
            failureMessage,
            ct,
            trackMutationPhase: false);

    private static Task<CommandResult> RunLocalMutationAsync(
        LocalUserPayload payload,
        Func<LocalUserPayload, LocalMutationState, CommandResult> action,
        string mutationName,
        string failureCode,
        string failureMessage,
        CancellationToken ct)
        => RunLocalMutationAsync(
            payload,
            action,
            mutationName,
            failureCode,
            failureMessage,
            ct,
            trackMutationPhase: true);

    private static Task<CommandResult> RunLocalMutationAsync(
        LocalUserPayload payload,
        Func<LocalUserPayload, LocalMutationState, CommandResult> action,
        string mutationName,
        string failureCode,
        string failureMessage,
        CancellationToken ct,
        bool trackMutationPhase)
        => Task.Run(
            () =>
            {
                ct.ThrowIfCancellationRequested();
                if (!TryAcquireMutationSlot(mutationName, payload.Username, DateTimeOffset.UtcNow, out var retryAfter))
                {
                    return Fail(
                        "local_user_rate_limited",
                        $"Managed local user {mutationName} is rate limited. Retry after {retryAfter.TotalSeconds:F0} seconds.",
                        payload,
                        executionStage: "before_execution");
                }

                var mutation = trackMutationPhase ? new LocalMutationState() : null;
                try
                {
                    var unsupported = EnsureLocalAccountsSupported(payload);
                    if (unsupported is not null)
                        return unsupported;

                    return action(payload, mutation ?? new LocalMutationState());
                }
                catch (Exception ex) when (ex is COMException or UnauthorizedAccessException or InvalidOperationException)
                {
                    _ = ex;
                    return Fail(
                        failureCode,
                        failureMessage,
                        payload,
                        executionStage: mutation?.ExecutionStage ?? "unknown",
                        mutationResultCode: mutation?.MutationResultCode,
                        mutationResultStatus: mutation?.MutationResultStatus);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _ = ex;
                    return Fail(
                        failureCode,
                        failureMessage,
                        payload,
                        executionStage: mutation?.ExecutionStage ?? "unknown",
                        mutationResultCode: mutation?.MutationResultCode,
                        mutationResultStatus: mutation?.MutationResultStatus);
                }
            },
            ct);

    private static CommandResult CreateOrRotateUser(
        LocalUserPayload payload,
        Func<LocalUserCommandPolicy> policyResolver,
        LocalMutationState mutation)
    {
        var policyFailure = CreatePolicyFailure(policyResolver, payload);
        if (policyFailure is not null) return policyFailure;

        using var computer = OpenComputer();
        if (TryFindUser(computer, payload.Username, out var existing))
        {
            if (existing is null)
                return Fail(
                    "local_user_lookup_failed",
                    "Local user lookup returned no entry.",
                    payload,
                    executionStage: "before_execution");

            using (existing)
            {
                if (!IsManagedByCerberus(existing, payload, allowLegacy: true))
                    return ManagedUserCollision(payload);

                var password = GeneratePassword();
                var encryptedPassword = EncryptPassword(password, payload);
                var rdpCredential = BuildRdpCredentialEnvelope(password, payload);
                policyFailure = CreatePolicyFailure(policyResolver, payload);
                if (policyFailure is not null) return policyFailure;
                if (!TryWriteManagedOwnership(payload, existing, mutation))
                    return Fail(
                        "managed_ownership_write_failed",
                        "Managed user ownership marker could not be persisted.",
                        payload,
                        executionStage: mutation.ExecutionStage,
                        mutationResultCode: mutation.MutationResultCode,
                        mutationResultStatus: mutation.MutationResultStatus);

                var rdpLogonRight = ShouldGrantRemoteDesktopMembership(
                    existingUser: true,
                    enableAccountExplicit: payload.EnableAccountExplicit,
                    enableAccount: payload.EnableAccount)
                    ? EnsureRemoteDesktopUserMembership(payload.Username)
                    : new RdpLogonRightResult("preserved", true);
                if (!rdpLogonRight.Granted)
                    return Fail(
                        "rdp_logon_right_failed",
                        "Remote Desktop Users membership could not be granted.",
                        payload,
                        rdpLogonRight.Status,
                        mutation.ExecutionStage,
                        mutation.MutationResultCode,
                        mutation.MutationResultStatus);

                existing.Invoke("SetPassword", password);
                existing.Properties["Description"].Value = ManagedDescription(payload);
                ApplyManagedPasswordPolicy(existing, payload.EnableAccountExplicit && payload.EnableAccount);
                existing.CommitChanges();
                mutation.MarkNativeMutationCommitted(
                    payload.CredentialRequestId is null ? "already_exists" : "password_rotated");
                var localSid = GetLocalSid(existing);
                return Success(
                    payload.CredentialRequestId is null ? "already_exists" : "password_rotated",
                    payload,
                    enabled: IsUserEnabled(payload.Username),
                    localSid: localSid.Value,
                    localSidStatus: localSid.Status,
                    encryptedPassword: encryptedPassword,
                    rdpCredential: rdpCredential,
                    rdpLogonRight: rdpLogonRight.Status);
            }
        }

        // An orphaned ownership key is not authority to adopt a different SAM identity.
        using var ownershipKey = Registry.LocalMachine.OpenSubKey(ManagedUserRegistryPath(payload.Username));
        if (ownershipKey is not null) return ManagedUserCollision(payload);
        policyFailure = CreatePolicyFailure(policyResolver, payload);
        if (policyFailure is not null) return policyFailure;
        mutation.MarkFirstWrite();
        using var user = computer.Children.Add(payload.Username, "user");
        var generatedPassword = GeneratePassword();
        user.Invoke("SetPassword", generatedPassword);
        user.Properties["FullName"].Value = payload.DisplayName ?? "Cerberus managed user";
        user.Properties["Description"].Value = ManagedDescription(payload);
        var enableCreatedAccount = payload.EnableAccountExplicit && payload.EnableAccount;
        ApplyManagedPasswordPolicyForNewUser(user, enableCreatedAccount);
        user.CommitChanges();
        mutation.MarkNativeMutationCommitted("created");
        if (!TryWriteManagedOwnership(payload, user, mutation))
        {
            TryRemoveUser(computer, payload.Username);
            return Fail(
                "managed_ownership_write_failed",
                "Managed user ownership marker could not be persisted.",
                payload,
                executionStage: mutation.ExecutionStage,
                mutationResultCode: mutation.MutationResultCode,
                mutationResultStatus: mutation.MutationResultStatus,
                compensationStatus: "attempted");
        }

        var createdRdpLogonRight = enableCreatedAccount
            ? EnsureRemoteDesktopUserMembership(payload.Username)
            : new RdpLogonRightResult("preserved", true);
        if (!createdRdpLogonRight.Granted)
        {
            RemoveManagedOwnership(payload.Username);
            TryRemoveUser(computer, payload.Username);
            return Fail(
                "rdp_logon_right_failed",
                "Remote Desktop Users membership could not be granted.",
                payload,
                createdRdpLogonRight.Status,
                mutation.ExecutionStage,
                mutation.MutationResultCode,
                mutation.MutationResultStatus,
                "attempted");
        }

        var createdSid = GetLocalSid(user);
        return Success(
            "created",
            payload,
            enabled: enableCreatedAccount,
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
