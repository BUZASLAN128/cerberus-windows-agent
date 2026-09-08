using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Integrations.Ad;

public static class ScopedAdCommandHandlers
{
    public const string ResultSchemaVersion = "agent.ad-user.result.v1";

    public static ICommandHandler[] CreateDefaultHandlers(AgentIdentity identity, IAgentLifecycleStateStore lifecycle,
        Func<AgentCommand, CancellationToken, Task<AdCommandAuthority>> authorize, IScopedAdUserProvider provider)
        => CreateHandlers(identity, lifecycle, authorize, provider, () => DateTimeOffset.UtcNow);

    internal static ICommandHandler[] CreateHandlers(AgentIdentity identity, IAgentLifecycleStateStore lifecycle,
        Func<AgentCommand, CancellationToken, Task<AdCommandAuthority>> authorize, IScopedAdUserProvider provider, Func<DateTimeOffset> now)
        => [new Handler("windows.ad_user.create", identity, lifecycle, authorize, provider, now),
            new Handler("windows.ad_user.disable", identity, lifecycle, authorize, provider, now),
            new Handler("windows.ad_user.delete", identity, lifecycle, authorize, provider, now)];

    private sealed class Handler(string type, AgentIdentity identity, IAgentLifecycleStateStore lifecycle,
        Func<AgentCommand, CancellationToken, Task<AdCommandAuthority>> authorize, IScopedAdUserProvider provider,
        Func<DateTimeOffset> now) : IAuthoritativeCommandExecutionGate
    {
        private readonly AsyncLocal<Execution?> _execution = new();
        public string Type => type;

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
            => ExecuteAuthorizedAsync(command, HandleAuthorizedAsync, ct);

        public async Task<CommandResult> ExecuteAuthorizedAsync(AgentCommand supplied,
            Func<AgentCommand, CancellationToken, Task<CommandResult>> execute, CancellationToken ct)
        {
            ScopedAdCommandPayload? parsed = null;
            try
            {
                if (supplied.Type != Type || !Bounded(supplied.Id) || !Bounded(supplied.IdempotencyKey) || !Bounded(supplied.LeaseId))
                    return Early("ad_authority_required");
                var before = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
                if (AgentLifecycleStates.IsDormant(before.State) || !before.QuiescenceComplete) return Early("ad_authority_required");
                var authority = await authorize(supplied, ct).ConfigureAwait(false);
                if (authority is null || authority.TenantId != identity.TenantId || authority.AgentId != identity.AgentId ||
                    authority.Command is null || authority.Command.Id != supplied.Id || authority.Command.Type != supplied.Type ||
                    authority.Command.IdempotencyKey != supplied.IdempotencyKey || authority.Command.LeaseId != supplied.LeaseId ||
                    authority.ExpiresAt.Offset != TimeSpan.Zero || authority.ExpiresAt <= now() || authority.ExpiresAt > now().AddSeconds(30))
                    return Early("ad_authority_required");
                var command = authority.Command with { Payload = JsonSerializer.SerializeToElement(authority.Command.Payload) };
                parsed = ScopedAdCommandPayload.Parse(command, identity);
                CommandResult result = Failure(parsed, "ad_authority_required");
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var remaining = authority.ExpiresAt - now();
                if (remaining <= TimeSpan.Zero) return result;
                deadline.CancelAfter(remaining);
                var ran = await lifecycle.ExecuteIfCurrentAsync(before.Generation, async _ =>
                {
                    if (authority.ExpiresAt <= now()) return;
                    var context = new Execution(command, parsed, authority.ExpiresAt);
                    _execution.Value = context;
                    try
                    {
                        result = await execute(command, deadline.Token).ConfigureAwait(false);
                        // A generic dispatcher exception/timeout is never allowed to return raw diagnostics for AD.
                        if (result.PostVerify is not Dictionary<string, object?>) result = Failure(parsed, "ad_outcome_uncertain");
                    }
                    catch (Exception) { result = Failure(parsed, "ad_outcome_uncertain"); }
                    finally { context.Active = false; _execution.Value = null; }
                    if (authority.ExpiresAt <= now() || deadline.IsCancellationRequested || context.ActivationInterrupted)
                    {
                        if (parsed.Phase == "activate" && parsed.ExpectedIdentity is not null)
                        {
                            using var cleanupDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                            var disabled = await provider.DisableAsync(parsed.Target, parsed.ExpectedIdentity,
                                "AD activation authority expired or execution was cancelled.", cleanupDeadline.Token).ConfigureAwait(false);
                            result = Failure(parsed, disabled.Success ? "ad_authority_required" : "ad_outcome_uncertain");
                        }
                        else result = Failure(parsed, "ad_authority_required");
                    }
                }, ct).ConfigureAwait(false);
                return ran ? result : Failure(parsed, "ad_authority_required");
            }
            catch (AdOperationDeniedException ex)
            {
                return parsed is null ? Early(ex.Code == "ad_command_invalid" ? "ad_command_invalid" : "ad_authority_required") : Failure(parsed, SafeCode(ex.Code));
            }
            catch (Exception) { return parsed is null ? Early("ad_authority_required") : Failure(parsed, "ad_outcome_uncertain"); }
        }

        public async Task<CommandResult> HandleAuthorizedAsync(AgentCommand command, CancellationToken ct)
        {
            var context = _execution.Value;
            if (context is null || !context.Active || !ReferenceEquals(context.Command, command) || context.ExpiresAt <= now())
                return Early("ad_authority_required");
            var payload = context.Payload;
            try
            {
                var result = Type switch
                {
                    "windows.ad_user.create" when payload.Phase == "prepare" => await provider.PrepareAsync(payload.Target, payload.CredentialRequest!, ct).ConfigureAwait(false),
                    "windows.ad_user.create" when payload.Phase == "activate" => await provider.ActivateAsync(payload.Target, payload.ExpectedIdentity!, payload.CredentialProfileId!, ct).ConfigureAwait(false),
                    "windows.ad_user.disable" => await provider.DisableAsync(payload.Target, payload.ExpectedIdentity!, payload.Reason, ct).ConfigureAwait(false),
                    "windows.ad_user.delete" => await provider.DeleteAsync(payload.Target, payload.ExpectedIdentity!, payload.ConfirmDelete, payload.Reason, ct).ConfigureAwait(false),
                    _ => new AdOperationResult(false, "ad_command_invalid")
                };
                var expectedCode = payload.Phase switch { "prepare" => "ad_prepared", "activate" => "ad_activated", _ => Type.EndsWith("disable", StringComparison.Ordinal) ? "ad_disabled" : "ad_deleted" };
                if (result.Success && (result.Code != expectedCode || result.Identity is null))
                    return Failure(payload, "ad_outcome_uncertain");
                var verify = PostVerify(payload, SafeCode(result.Code), result.Identity);
                if (result.Success && payload.Phase == "prepare")
                {
                    if (result.PreparedCredential is not { } preparedCredential ||
                        preparedCredential.Request != payload.CredentialRequest)
                        return Failure(payload, "ad_outcome_uncertain");
                    verify["credential_request_id"] = preparedCredential.Request.CredentialRequestId;
                    verify["rdp_credential"] = preparedCredential.Envelope;
                }
                return new(result.Success ? "DONE" : "FAILED", result.Success ? 0 : 1, null,
                    result.Success ? null : "AD operation was not completed.", verify);
            }
            catch (Exception) { return Failure(payload, "ad_outcome_uncertain"); }
            finally
            {
                // Dispatcher timeouts use a child token; propagate interruption to the outer compensation owner.
                if (payload.Phase == "activate" && ct.IsCancellationRequested) context.ActivationInterrupted = true;
            }
        }

        private static bool Bounded(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 256 && !value.Any(char.IsControl);
        private sealed class Execution(AgentCommand command, ScopedAdCommandPayload payload, DateTimeOffset expiresAt)
        {
            public AgentCommand Command { get; } = command;
            public ScopedAdCommandPayload Payload { get; } = payload;
            public DateTimeOffset ExpiresAt { get; } = expiresAt;
            public bool Active { get; set; } = true;
            public bool ActivationInterrupted { get; set; }
        }
    }

    private static CommandResult Early(string code) => new("FAILED", 1, null, "AD command authority or payload is invalid.",
        new Dictionary<string, object?> { ["schema_version"] = ResultSchemaVersion, ["code"] = code });
    private static CommandResult Failure(ScopedAdCommandPayload payload, string code) =>
        new("FAILED", 1, null, "AD operation was not completed.", PostVerify(payload, code, null));
    private static Dictionary<string, object?> PostVerify(ScopedAdCommandPayload payload, string code, AdUserIdentity? identity)
    {
        var target = payload.Target;
        var result = new Dictionary<string, object?>
        {
            ["schema_version"] = ResultSchemaVersion, ["code"] = code,
            ["managed_account_id"] = target.Binding.ManagedAccountId, ["assignment_id"] = target.Binding.AssignmentId,
            ["scope_id"] = target.Binding.ScopeId, ["username"] = target.Binding.Username,
            ["domain_guid"] = target.DomainGuid, ["ou_guid"] = target.OuGuid, ["domain_dns_name"] = target.DomainDnsName
        };
        if (payload.Phase is not null) result["phase"] = payload.Phase;
        if (identity is not null) { result["object_guid"] = identity.ObjectGuid; result["sid"] = identity.Sid; }
        return result;
    }

    private static string SafeCode(string code) => Codes.Contains(code) ? code : "ad_outcome_uncertain";
    private static readonly HashSet<string> Codes = new(StringComparer.Ordinal)
    {
        "ad_prepared", "ad_activated", "ad_disabled", "ad_deleted", "ad_authority_required", "ad_credential_pending",
        "ad_credential_expired", "ad_command_invalid", "ad_account_disabled", "ad_account_retired", "ad_busy",
        "ad_cancelled_before_execution", "ad_controller_mismatch", "ad_create_not_disabled", "ad_create_readback_failed",
        "ad_delegation_policy_required", "ad_delete_confirmation_required", "ad_directory_access_denied",
        "ad_directory_attribute_invalid", "ad_directory_attribute_missing", "ad_directory_identity_ambiguous",
        "ad_directory_policy_denied", "ad_directory_result_out_of_bounds", "ad_directory_unavailable", "ad_directory_value_invalid",
        "ad_disable_before_delete", "ad_domain_controller_denied", "ad_domain_mismatch", "ad_group_protection_unavailable",
        "ad_invalid_password_input", "ad_leaf_user_required", "ad_machine_identity_invalid", "ad_machine_principal_denied",
        "ad_machine_role_unavailable", "ad_not_domain_member", "ad_object_guard_denied", "ad_object_identity_invalid",
        "ad_object_missing", "ad_ou_mismatch", "ad_outcome_uncertain", "ad_owned_object_missing", "ad_ownership_invalid",
        "ad_ownership_mismatch", "ad_ownership_required", "ad_partial_account_enabled", "ad_password_readback_failed",
        "ad_password_requires_disabled_user", "ad_policy_invalid", "ad_readback_failed", "ad_reason_required",
        "ad_retired_object_present", "ad_scope_denied", "ad_secure_channel_required", "ad_system_identity_required",
        "ad_unowned_collision", "ad_username_invalid", "ad_windows_required"
    };
}
