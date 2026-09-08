using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Security;

/// <summary>
/// Secure storage for agent credentials using Windows DPAPI encryption.
/// Supports both user-scope and machine-scope encryption.
/// </summary>
public sealed class DpapiSecretStore : ISecretStore
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);
    private readonly string _path;
    private readonly SecretStoreScope _scope;
    private readonly bool _canonicalMachine;
    private readonly bool _protectedPending;

    /// <summary>
    /// Initializes a new instance of the <see cref="DpapiSecretStore"/> class.
    /// </summary>
    /// <param name="scope">Encryption scope (user or machine).</param>
    /// <param name="baseDir">Base directory for secrets file (optional, defaults to AppData).</param>
    public DpapiSecretStore(SecretStoreScope scope = SecretStoreScope.Machine, string? baseDir = null)
    {
        _scope = scope;
        baseDir ??= GetDefaultBaseDir(scope);
        _path = Path.Combine(baseDir, "secrets.json");
        _canonicalMachine = scope == SecretStoreScope.Machine &&
            string.Equals(Path.GetFullPath(_path), GetDefaultSecretsPath(SecretStoreScope.Machine), StringComparison.OrdinalIgnoreCase);
        _protectedPending = scope == SecretStoreScope.Machine &&
            string.Equals(Path.GetFullPath(baseDir), AgentCredentialPublication.PendingDirectory, StringComparison.OrdinalIgnoreCase);
        if (_protectedPending)
            AgentCredentialPublication.ValidateProtectedItem(baseDir);
        else if (!_canonicalMachine)
            Directory.CreateDirectory(baseDir);
    }

    public static string GetDefaultBaseDir(SecretStoreScope scope)
    {
        var root = scope == SecretStoreScope.User
            ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            : Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return Path.Combine(root, "CerberusAgent");
    }

    public static string GetDefaultSecretsPath(SecretStoreScope scope)
        => Path.Combine(GetDefaultBaseDir(scope), "secrets.json");

    /// <summary>
    /// Saves agent credentials to encrypted storage.
    /// </summary>
    /// <param name="identity">Agent identity (agent ID and tenant ID).</param>
    /// <param name="refreshToken">Refresh token for authentication.</param>
    /// <param name="privateKeyPem">RSA private key in PEM format.</param>
    /// <param name="backendUrl">Backend API URL.</param>
    /// <param name="tailscaleLoginServer">Tailscale login server URL (optional).</param>
    /// <param name="tailscaleAuthkey">Tailscale auth key (optional).</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task SaveAsync(
        AgentIdentity identity,
        string refreshToken,
        string privateKeyPem,
        string backendUrl,
        string? tailscaleLoginServer,
        string? tailscaleAuthkey,
        CancellationToken ct)
    {
        using var access = _canonicalMachine ? await AgentCredentialPublication.AcquireActiveAccessAsync(ct).ConfigureAwait(false) : null;
        if (_protectedPending) AgentCredentialPublication.ValidateProtectedItem(_path, allowMissing: true);
        var payload = new SecretPayload(
            "cerberus-agent-secret.v2",
            identity.AgentId,
            identity.TenantId,
            refreshToken,
            privateKeyPem,
            backendUrl,
            tailscaleLoginServer,
            tailscaleAuthkey);
        var raw = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOpts);
        var enc = ProtectedData.Protect(
            raw,
            optionalEntropy: null,
            _scope == SecretStoreScope.User ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);

        // Publish complete encrypted payloads atomically. A cancelled/failed
        // enrollment or refresh must not truncate the previous registration.
        var temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = _canonicalMachine || _protectedPending
                ? AgentCredentialPublication.CreateProtectedFile(temporary)
                : new FileStream(temporary, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough | FileOptions.Asynchronous))
            {
                if (!_canonicalMachine && !_protectedPending) LockDownAcl(temporary, _scope);
                await stream.WriteAsync(enc.AsMemory(), ct).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            ct.ThrowIfCancellationRequested();
            File.Move(temporary, _path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    /// <summary>
    /// Loads agent credentials from encrypted storage.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>Tuple containing agent identity, tokens, and configuration.</returns>
    /// <exception cref="InvalidOperationException">Thrown when decryption or deserialization fails.</exception>
    public async Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)>
        LoadAsync(CancellationToken ct)
    {
        using var access = _canonicalMachine ? await AgentCredentialPublication.AcquireActiveAccessAsync(ct).ConfigureAwait(false) : null;
        if (_protectedPending) AgentCredentialPublication.ValidateProtectedItem(_path);
        var enc = await File.ReadAllBytesAsync(_path, ct).ConfigureAwait(false);
        var raw = ProtectedData.Unprotect(
            enc,
            optionalEntropy: null,
            _scope == SecretStoreScope.User ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);
        var payload = JsonSerializer.Deserialize<SecretPayload>(raw, JsonOpts)
                      ?? throw new InvalidOperationException("Secret payload decode failed.");

        return (
            new AgentIdentity(payload.AgentId, payload.TenantId),
            payload.RefreshToken,
            payload.PrivateKeyPem,
            payload.BackendUrl,
            payload.TailscaleLoginServer,
            payload.TailscaleAuthkey
        );
    }

    public async Task ClearAsync(CancellationToken ct)
    {
        using var access = _canonicalMachine ? await AgentCredentialPublication.AcquireActiveAccessAsync(ct).ConfigureAwait(false) : null;
        if (_protectedPending) AgentCredentialPublication.ValidateProtectedItem(_path, allowMissing: true);
        ct.ThrowIfCancellationRequested();
        if (!File.Exists(_path))
            return;

        var length = new FileInfo(_path).Length;
        if (length > 0)
        {
            await using var stream = new FileStream(
                _path,
                FileMode.Open,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                FileOptions.WriteThrough | FileOptions.Asynchronous);
            var zeros = new byte[Math.Min(length, 8192)];
            var remaining = length;
            while (remaining > 0)
            {
                ct.ThrowIfCancellationRequested();
                var write = (int)Math.Min(zeros.Length, remaining);
                await stream.WriteAsync(zeros.AsMemory(0, write), ct).ConfigureAwait(false);
                remaining -= write;
            }
            await stream.FlushAsync(ct).ConfigureAwait(false);
        }

        File.Delete(_path);
    }

    private static void LockDownAcl(string filePath, SecretStoreScope scope)
    {
        // Best-effort ACL hardening. This runs in user context during onboarding and can be
        // restricted by local policy; do not fail registration if hardening cannot be applied.
        try
        {
            var fileInfo = new FileInfo(filePath);
            var fs = new FileSecurity();

            fs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Setting owner to SYSTEM may require elevation; ignore failures.
            try { fs.SetOwner(new NTAccount("SYSTEM")); }
            catch (Exception ex) { Trace.TraceWarning($"Cerberus agent secret owner hardening failed: {ex.GetType().Name}"); }

            fs.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            fs.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            // User-scope onboarding secrets must remain available to the tray user.
            // Machine-scope service secrets must not add an explicit interactive-user ACE.
            if (scope == SecretStoreScope.User)
            {
                var me = WindowsIdentity.GetCurrent().User;
                if (me is not null)
                {
                    fs.AddAccessRule(new FileSystemAccessRule(
                        me,
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));
                }
            }

            fileInfo.SetAccessControl(fs);
        }
        catch (Exception ex)
        {
            Trace.TraceWarning($"Cerberus agent secret ACL hardening failed: {ex.GetType().Name}");
        }
    }

    // Backward compatible: older payloads won't have tailscale fields; they deserialize as null.
    private sealed record SecretPayload(
        string? SchemaVersion,
        string AgentId,
        string TenantId,
        string RefreshToken,
        string PrivateKeyPem,
        string BackendUrl,
        string? TailscaleLoginServer,
        string? TailscaleAuthkey);
}
