using System.Text.RegularExpressions;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Integrations.Ad;

/// <summary>Disabled-first creation and immutable ownership. Failed persistence never enables or adopts an account.</summary>
public sealed partial class ScopedAdUserProvider : IScopedAdUserProvider
{
    private readonly AgentIdentity _identity;
    private readonly Func<IReadOnlyList<AdScope>> _loadScopes;
    private readonly IAdDirectoryBoundary _directory;
    private readonly IAdOwnershipStore _store;
    // Fixed stripes bound lock memory; the process-wide lock also serializes separate provider instances.
    private static readonly SemaphoreSlim[] Gates = Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    public ScopedAdUserProvider(AgentIdentity identity, IEnumerable<AdScope> enabledScopes,
        IAdDirectoryBoundary directory, IAdOwnershipStore store)
    {
        _identity = identity;
        var scopes = enabledScopes.ToArray();
        _loadScopes = () => scopes;
        _directory = directory;
        _store = store;
    }

    public ScopedAdUserProvider(AgentIdentity identity, ProtectedAdScopePolicy policy,
        IAdDirectoryBoundary directory, IAdOwnershipStore store)
    {
        _identity = identity;
        _loadScopes = () => policy.Load(identity);
        _directory = directory;
        _store = store;
    }

    public Task<AdOperationResult> CreateAsync(AdAccountBinding binding, string initialPassword, bool activate, CancellationToken ct)
        => Execute(binding, ct, (session, scope) =>
        {
            if (string.IsNullOrEmpty(initialPassword) || initialPassword.Length is < 24 or > 256)
                return new(false, "ad_invalid_password_input");
            var owned = Load(binding, scope);
            var existing = owned is not null;
            if (owned?.Deleted == true) return new(false, "ad_account_retired", owned.Identity);
            if (owned?.DisableRequested == true) return new(false, "ad_account_disabled", owned.Identity);
            if (owned is null)
            {
                if (session.FindUsername(binding.Username) is not null) return new(false, "ad_unowned_collision");
                ct.ThrowIfCancellationRequested();
                var created = session.CreateDisabled(binding.Username);
                Validate(created, binding, scope, created.Identity);
                if (!created.Disabled) throw new AdOperationDeniedException("ad_create_not_disabled");
                owned = new(binding, scope, created.Identity, false, false);
                // Losing this write leaves a disabled unowned object requiring administrative reconciliation.
                _store.Write(owned);
            }
            var current = RequireOwned(session, owned);
            if (!owned.PasswordInitialized)
            {
                if (!current.Disabled) throw new AdOperationDeniedException("ad_partial_account_enabled");
                ct.ThrowIfCancellationRequested();
                session.InitializePassword(owned.Identity, binding.Username, initialPassword);
                owned = owned with { PasswordInitialized = true };
                _store.Write(owned);
            }
            current = RequireOwned(session, owned);
            if (activate && current.Disabled)
            {
                ct.ThrowIfCancellationRequested();
                session.SetDisabled(owned.Identity, binding.Username, false);
                current = RequireOwned(session, owned);
            }
            if (ct.IsCancellationRequested) return new(false, "ad_outcome_uncertain", owned.Identity);
            return new(current.Disabled != activate, current.Disabled == activate ? "ad_readback_failed" :
                existing ? "ad_existing" : "ad_created", owned.Identity);
        });

    public Task<AdOperationResult> DisableAsync(AdAccountBinding binding, string reason, CancellationToken ct)
        => DisableCore(binding, reason, ct);

    public Task<AdOperationResult> DisableAsync(AdCommandTarget target, AdUserIdentity expectedIdentity, string reason, CancellationToken ct)
        => DisableCore(target.Binding, reason, ct, target, expectedIdentity);

    private Task<AdOperationResult> DisableCore(AdAccountBinding binding, string reason, CancellationToken ct,
        AdCommandTarget? target = null, AdUserIdentity? expectedIdentity = null)
        => Execute(binding, ct, (session, scope) =>
        {
            if (target is not null) ValidateTarget(target, scope);
            if (!ValidReason(reason)) return new(false, "ad_reason_required");
            var owned = Load(binding, scope) ?? throw new AdOperationDeniedException("ad_ownership_required");
            if (expectedIdentity is not null && owned.Identity != expectedIdentity) return new(false, "ad_ownership_mismatch");
            if (owned.Deleted) return new(false, "ad_account_retired", owned.Identity);
            var current = RequireOwned(session, owned);
            // A delayed create replay must not reactivate an account after a safety disable request.
            owned = owned with { DisableRequested = true };
            _store.Write(owned);
            if (!current.Disabled)
            {
                ct.ThrowIfCancellationRequested();
                session.SetDisabled(owned.Identity, binding.Username, true);
            }
            current = RequireOwned(session, owned);
            return new(current.Disabled && !ct.IsCancellationRequested,
                ct.IsCancellationRequested ? "ad_outcome_uncertain" : current.Disabled ? "ad_disabled" : "ad_readback_failed", owned.Identity);
        });

    public Task<AdOperationResult> DeleteAsync(AdAccountBinding binding, bool confirmed, string reason, CancellationToken ct)
        => DeleteCore(binding, confirmed, reason, ct);

    public Task<AdOperationResult> DeleteAsync(AdCommandTarget target, AdUserIdentity expectedIdentity, bool confirmed, string reason, CancellationToken ct)
        => DeleteCore(target.Binding, confirmed, reason, ct, target, expectedIdentity);

    private Task<AdOperationResult> DeleteCore(AdAccountBinding binding, bool confirmed, string reason, CancellationToken ct,
        AdCommandTarget? target = null, AdUserIdentity? expectedIdentity = null)
        => Execute(binding, ct, (session, scope) =>
        {
            if (target is not null) ValidateTarget(target, scope);
            if (!confirmed || !ValidReason(reason)) return new(false, "ad_delete_confirmation_required");
            var owned = Load(binding, scope) ?? throw new AdOperationDeniedException("ad_ownership_required");
            if (expectedIdentity is not null && owned.Identity != expectedIdentity) return new(false, "ad_ownership_mismatch");
            var current = session.Read(owned.Identity.ObjectGuid);
            if (current is not null)
            {
                if (owned.Deleted) return new(false, "ad_retired_object_present", owned.Identity);
                Validate(current, binding, scope, owned.Identity);
                if (!current.Disabled) return new(false, "ad_disable_before_delete", owned.Identity);
                ct.ThrowIfCancellationRequested();
                session.DeleteLeaf(owned.Identity, binding.Username);
                if (session.Read(owned.Identity.ObjectGuid) is not null) return new(false, "ad_readback_failed", owned.Identity);
            }
            // A missing GUID is idempotent only with the previously persisted exact ownership record.
            _store.Write(owned with { Deleted = true });
            return new(!ct.IsCancellationRequested, ct.IsCancellationRequested ? "ad_outcome_uncertain" : "ad_deleted", owned.Identity);
        });

    private async Task<AdOperationResult> Execute(AdAccountBinding b, CancellationToken ct,
        Func<IAdDirectorySession, AdScope, AdOperationResult> operation)
    {
        if (b is null || b.TenantId != _identity.TenantId || b.AgentId != _identity.AgentId ||
            new[] { b.TenantId, b.AgentId, b.ManagedAccountId, b.AssignmentId, b.ScopeId }.Any(v =>
                string.IsNullOrWhiteSpace(v) || v.Length > 128 || v.Any(char.IsControl)) ||
            b.Username is null || !Regex.IsMatch(b.Username, "\\A[a-zA-Z][a-zA-Z0-9_-]{0,19}\\z"))
            return new(false, "ad_scope_denied");
        var gate = Gates[(uint)StringComparer.OrdinalIgnoreCase.GetHashCode(b.Username) % Gates.Length];
        try
        {
            if (!await gate.WaitAsync(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false)) return new(false, "ad_busy");
        }
        catch (OperationCanceledException) { return new(false, "ad_cancelled_before_execution"); }
        try
        {
            ct.ThrowIfCancellationRequested();
            var scope = _loadScopes().SingleOrDefault(s => s.ScopeId == b.ScopeId);
            if (scope is null) return new(false, "ad_scope_denied");
            using var lease = _store.AcquireLease(b);
            using var session = _directory.Open(scope, ct);
            session.VerifyScope();
            return operation(session, scope);
        }
        catch (AdOperationDeniedException ex) { return new(false, ex.Code); }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.COMException or IOException or
            UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException or
            OperationCanceledException or System.Text.Json.JsonException)
        {
            // Never return raw directory exceptions: they can contain DNs or credential-related diagnostics.
            return new(false, "ad_outcome_uncertain");
        }
        finally { gate.Release(); }
    }

    private AdOwnership? Load(AdAccountBinding binding, AdScope scope)
    {
        var owned = _store.Read(binding);
        if (owned is not null && (owned.Binding != binding || owned.Scope != scope))
            throw new AdOperationDeniedException("ad_ownership_mismatch");
        return owned;
    }

    private static AdUserState RequireOwned(IAdDirectorySession session, AdOwnership owned)
    {
        session.VerifyScope();
        var current = session.Read(owned.Identity.ObjectGuid) ?? throw new AdOperationDeniedException("ad_owned_object_missing");
        Validate(current, owned.Binding, owned.Scope, owned.Identity);
        return current;
    }

    private static void Validate(AdUserState current, AdAccountBinding b, AdScope scope, AdUserIdentity expected)
    {
        if (expected.ObjectGuid == Guid.Empty || string.IsNullOrWhiteSpace(expected.Sid) || current.Identity != expected ||
            current.ParentGuid != scope.OuGuid || !StringComparer.OrdinalIgnoreCase.Equals(current.Username, b.Username) ||
            current.Protected || !current.LeafUser)
            throw new AdOperationDeniedException("ad_object_guard_denied");
    }

    private static bool ValidReason(string reason) => !string.IsNullOrWhiteSpace(reason) && reason.Length <= 512 && !reason.Any(char.IsControl);
}
