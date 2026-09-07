namespace Cerberus.Agent.Integrations.Ad;

public sealed partial class ScopedAdUserProvider
{
    public Task<AdOperationResult> PrepareAsync(AdCommandTarget target, AdCredentialRequest request, CancellationToken ct)
        => Execute(target.Binding, ct, (session, scope) =>
        {
            ValidateTarget(target, scope);
            ValidateCredentialRequest(request);
            var binding = target.Binding;
            var owned = Load(binding, scope);
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
                _store.Write(owned);
            }
            var current = RequireOwned(session, owned);
            if (owned.PasswordInitialized)
            {
                if (owned.PreparedCredential?.Request != request)
                    return new(false, "ad_credential_pending", owned.Identity);
                // Return the original tenant-encrypted result; replay never generates or changes a password.
                return new(true, "ad_prepared", owned.Identity, owned.PreparedCredential);
            }
            if (!current.Disabled) return new(false, "ad_partial_account_enabled", owned.Identity);
            ct.ThrowIfCancellationRequested();
            var password = RdpCredentialCodec.GeneratePassword();
            var envelope = RdpCredentialCodec.Encrypt(password, binding.Username, scope.DomainDnsName, request.Metadata);
            owned = owned with { PreparedCredential = new(request, envelope) };
            // Only tenant-encrypted material is persisted. Crash recovery while uninitialized resets a still-disabled user.
            _store.Write(owned);
            ct.ThrowIfCancellationRequested();
            session.InitializePassword(owned.Identity, binding.Username, password);
            owned = owned with { PasswordInitialized = true };
            _store.Write(owned);
            current = RequireOwned(session, owned);
            if (!current.Disabled || ct.IsCancellationRequested)
                return new(false, "ad_outcome_uncertain", owned.Identity);
            if (request.ExpiresAt <= DateTimeOffset.UtcNow) return new(false, "ad_credential_expired", owned.Identity);
            return new(true, "ad_prepared", owned.Identity, owned.PreparedCredential);
        });

    public Task<AdOperationResult> ActivateAsync(AdCommandTarget target, AdUserIdentity expectedIdentity,
        string credentialProfileId, CancellationToken ct)
        => Execute(target.Binding, ct, (session, scope) =>
        {
            ValidateTarget(target, scope);
            var owned = Load(target.Binding, scope) ?? throw new AdOperationDeniedException("ad_ownership_required");
            if (owned.Identity != expectedIdentity) return new(false, "ad_ownership_mismatch");
            if (owned.Deleted) return new(false, "ad_account_retired", owned.Identity);
            if (owned.DisableRequested) return new(false, "ad_account_disabled", owned.Identity);
            if (!owned.PasswordInitialized || owned.PreparedCredential is null ||
                owned.PreparedCredential.Request.Metadata.CredentialProfileId != credentialProfileId)
                return new(false, "ad_credential_pending", owned.Identity);
            if (owned.PreparedCredential.Request.ExpiresAt <= DateTimeOffset.UtcNow)
                return new(false, "ad_credential_expired", owned.Identity);
            var current = RequireOwned(session, owned);
            if (current.Disabled)
            {
                ct.ThrowIfCancellationRequested();
                session.SetDisabled(owned.Identity, target.Binding.Username, false);
            }
            current = RequireOwned(session, owned);
            return new(!current.Disabled && !ct.IsCancellationRequested,
                ct.IsCancellationRequested ? "ad_outcome_uncertain" : current.Disabled ? "ad_readback_failed" : "ad_activated", owned.Identity);
        });

    private static void ValidateTarget(AdCommandTarget target, AdScope scope)
    {
        if (target.DomainGuid != scope.DomainGuid || target.OuGuid != scope.OuGuid ||
            !StringComparer.OrdinalIgnoreCase.Equals(target.DomainDnsName, scope.DomainDnsName))
            throw new AdOperationDeniedException("ad_scope_denied");
    }

    internal static void ValidateCredentialRequest(AdCredentialRequest request, bool requireFresh = true)
    {
        if (request is null || !Guid.TryParse(request.CredentialRequestId, out var requestId) || requestId == Guid.Empty ||
            request.Metadata is null || string.IsNullOrWhiteSpace(request.Metadata.PublicKeyPem) ||
            request.Metadata.PublicKeyPem.Length > 4096 || request.Metadata.PublicKeyPem.Contains("PRIVATE KEY", StringComparison.Ordinal) ||
            request.Metadata.KeyVersion is null or <= 0 ||
            string.IsNullOrWhiteSpace(request.Metadata.PublicKeyFingerprint) || request.Metadata.PublicKeyFingerprint.Length != 64 ||
            string.IsNullOrWhiteSpace(request.Metadata.Aad) || request.Metadata.Aad.Length > 2048 ||
            RdpCredentialCodec.ValidationError(request.Metadata) is not null)
            throw new AdOperationDeniedException("ad_command_invalid");
        if (request.ExpiresAt.Offset != TimeSpan.Zero || request.ExpiresAt == default)
            throw new AdOperationDeniedException("ad_command_invalid");
        if (requireFresh && request.ExpiresAt <= DateTimeOffset.UtcNow)
            throw new AdOperationDeniedException("ad_credential_expired");
    }
}
