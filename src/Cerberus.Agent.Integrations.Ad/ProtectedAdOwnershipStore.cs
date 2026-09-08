using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Integrations.Ad;

/// <summary>Machine authority records, containing no passwords. Unsafe existing paths are rejected, never repaired into trust.</summary>
public sealed class ProtectedAdOwnershipStore : IAdOwnershipStore
{
    private const int MaxRecordBytes = 16384;
    private const int MaxFiles = 8192;
    private readonly string _root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CerberusAgent", "Privileged", "DirectoryUsers");

    public IDisposable AcquireLease(AdAccountBinding binding)
    {
        EnsureRoot();
        // Global OS file lease serializes separate service processes as well as usernames/account aliases.
        var path = Path.Combine(_root, "ownership.lock");
        AgentUpdateSecurity.ValidateProtectedPath(path, _root, allowMissing: true);
        var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            AgentUpdateSecurity.ValidateProtectedPath(path, _root, allowMissing: false);
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    public AdOwnership? Read(AdAccountBinding binding)
    {
        EnsureRoot();
        var path = RecordPath(binding);
        AgentUpdateSecurity.ValidateProtectedPath(path, _root, allowMissing: true);
        if (!File.Exists(path)) return null;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 or > MaxRecordBytes) throw new InvalidOperationException("AD ownership record exceeds bounds.");
        var bytes = new byte[(int)stream.Length];
        stream.ReadExactly(bytes);
        var record = Decode(bytes);
        if (record.Binding != binding)
            throw new AdOperationDeniedException("ad_ownership_mismatch");
        return record;
    }

    /// <summary>Parse bounded persisted data as untrusted input even after filesystem provenance was verified.</summary>
    public static AdOwnership Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is <= 0 or > MaxRecordBytes) throw new AdOperationDeniedException("ad_ownership_invalid");
        AdOwnership? record;
        try { record = JsonSerializer.Deserialize<AdOwnership>(bytes); }
        catch (JsonException) { throw new AdOperationDeniedException("ad_ownership_invalid"); }
        if (record?.Binding is null || record.Scope is null || record.Identity is null ||
            record.Identity.ObjectGuid == Guid.Empty || record.Scope.OuGuid == Guid.Empty || record.Scope.DomainGuid == Guid.Empty ||
            new[] { record.Binding.TenantId, record.Binding.AgentId, record.Binding.AssignmentId,
                record.Binding.ManagedAccountId, record.Binding.ScopeId, record.Binding.Username,
                record.Scope.ScopeId, record.Scope.ControllerFqdn, record.Identity.Sid }.Any(v =>
                    string.IsNullOrWhiteSpace(v) || v.Length > 256 || v.Any(char.IsControl)))
            throw new AdOperationDeniedException("ad_ownership_invalid");
        if (record.PreparedCredential is not null)
        {
            try
            {
                var prepared = record.PreparedCredential;
                ScopedAdUserProvider.ValidateCredentialRequest(prepared.Request, requireFresh: false);
                var metadata = prepared.Request.Metadata;
                var envelope = prepared.Envelope;
                if (envelope is null || envelope.AuthType != "password" ||
                    envelope.CredentialId != metadata.CredentialProfileId || envelope.TenantKeyId != metadata.TenantKeyId ||
                    envelope.KeyVersion != metadata.KeyVersion || envelope.CipherAlg != metadata.CipherAlg ||
                    envelope.AadHash != metadata.AadHash || envelope.UsernameHint != record.Binding.Username ||
                    envelope.Domain != record.Scope.DomainDnsName ||
                    Convert.FromBase64String(envelope.CipherNonce).Length != 12 ||
                    Convert.FromBase64String(envelope.Ciphertext).Length is < 17 or > 4096)
                    throw new AdOperationDeniedException("ad_ownership_invalid");
                using var rsa = RSA.Create();
                rsa.ImportFromPem(metadata.PublicKeyPem);
                if (Convert.FromBase64String(envelope.WrappedDek).Length != rsa.KeySize / 8)
                    throw new AdOperationDeniedException("ad_ownership_invalid");
            }
            catch (Exception ex) when (ex is AdOperationDeniedException or ArgumentException or FormatException or CryptographicException)
            { throw new AdOperationDeniedException("ad_ownership_invalid"); }
        }
        return record;
    }

    public void Write(AdOwnership ownership)
    {
        EnsureRoot();
        var path = RecordPath(ownership.Binding);
        var previous = Read(ownership.Binding);
        ValidateTransition(previous, ownership);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(ownership);
        _ = Decode(bytes);
        if (bytes.Length > MaxRecordBytes) throw new InvalidOperationException("AD ownership record exceeds bounds.");
        var temporary = Path.Combine(_root, Guid.NewGuid().ToString("N") + ".tmp");
        AgentUpdateSecurity.ValidateProtectedPath(temporary, _root, allowMissing: true);
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            AgentUpdateSecurity.ValidateProtectedPath(temporary, _root, allowMissing: false);
            AgentUpdateSecurity.ValidateProtectedPath(path, _root, allowMissing: true);
            File.Move(temporary, path, overwrite: true);
            if (Read(ownership.Binding) != ownership) throw new InvalidOperationException("AD ownership readback failed.");
        }
        finally
        {
            AgentUpdateSecurity.ValidateProtectedPath(temporary, _root, allowMissing: true);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    internal static void ValidateTransition(AdOwnership? previous, AdOwnership ownership)
    {
        if (previous is not null && (previous.Binding != ownership.Binding || previous.Scope != ownership.Scope ||
            previous.Identity != ownership.Identity || previous.Deleted && !ownership.Deleted ||
            previous.DisableRequested && !ownership.DisableRequested ||
            previous.PasswordInitialized && (!ownership.PasswordInitialized || previous.PreparedCredential != ownership.PreparedCredential)))
            throw new AdOperationDeniedException("ad_ownership_mismatch");
    }

    private void EnsureRoot()
    {
        if (!AgentUpdateSecurity.IsLocalSystem()) throw new AdOperationDeniedException("ad_system_identity_required");
        AgentUpdateSecurity.EnsureProtectedRoot(_root);
        if (Directory.EnumerateFileSystemEntries(_root).Take(MaxFiles + 1).Count() > MaxFiles)
            throw new InvalidOperationException("AD ownership storage capacity exceeded.");
    }

    private string RecordPath(AdAccountBinding binding)
    {
        var key = JsonSerializer.Serialize(new[] { binding.TenantId, binding.AgentId, binding.ManagedAccountId });
        return Path.Combine(_root, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))) + ".json");
    }
}
