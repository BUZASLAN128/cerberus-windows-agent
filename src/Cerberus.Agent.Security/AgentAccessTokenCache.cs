using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Security;

/// <summary>Optional, service-only storage for a short-lived access token.</summary>
public sealed class AgentAccessTokenCache
{
    private const string Schema = "agent.access-token.v1";
    private const int MaxBytes = 16 * 1024;
    private static readonly byte[] CerberusEntropy = Encoding.ASCII.GetBytes("cerberus-agent-access-token.v1");
    private static readonly byte[] SecondaryEntropy = Encoding.ASCII.GetBytes("secondary-agent-access-token.v1");
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        RespectRequiredConstructorParameters = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 2,
    };

    private readonly string _directory;
    private readonly bool _production;
    private readonly bool _canonical;
    private readonly SecurityIdentifier? _isolatedAuthority;
    private bool _disabled;

    public static AgentAccessTokenCache Machine { get; } = new(
        Path.Combine(DpapiSecretStore.GetDefaultBaseDir(SecretStoreScope.Machine), "token-cache"),
        production: true, canonical: true);

    internal AgentAccessTokenCache(string directory, bool production)
        : this(directory, production, canonical: false) { }

    // Exercise native ACLs and machine DPAPI using a disposable directory and the fixture's own user SID.
    internal AgentAccessTokenCache(string directory, SecurityIdentifier isolatedAuthority)
        : this(Path.GetFullPath(directory), production: true, canonical: false)
    {
        var temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
        if (!AgentUpdateSecurity.IsUnderDirectory(_directory, temp) ||
            string.Equals(Path.TrimEndingDirectorySeparator(_directory), temp, StringComparison.OrdinalIgnoreCase) ||
            AgentUpdateSecurity.IsUnderDirectory(_directory, DpapiSecretStore.GetDefaultBaseDir(SecretStoreScope.Machine)))
            throw new ArgumentException("Isolated cache storage requires a temporary child path.", nameof(directory));
        _isolatedAuthority = isolatedAuthority ?? throw new ArgumentNullException(nameof(isolatedAuthority));
    }

    private AgentAccessTokenCache(string directory, bool production, bool canonical)
        => (_directory, _production, _canonical) = (directory, production, canonical);

    internal async Task<CachedAccessToken?> ReadAsync(AgentIdentity identity, string backend, string key, long generation,
        DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            using var access = await AcquireAccessAsync(ct).ConfigureAwait(false);
            if (!ValidateDirectory(create: false)) return null;

            var path = GetPath(identity.Product);
            try
            {
                var attributes = GetAttributes(path);
                if (attributes is null) return null;
                if (IsRegularFile(attributes.Value) && (!_production || HasExpectedAcl(new FileInfo(path).GetAccessControl())))
                {
                    var payload = await ReadPayloadAsync(path, identity.Product, ct).ConfigureAwait(false);
                    if (payload is not null && IsCurrent(payload, identity, backend, key, generation, now))
                        return new(payload.AccessToken, payload.ExpiresAtUtc);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // An unreadable or corrupt entry is a cache miss.
            }
            TryDeleteFile(path);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Credential publication and directory checks must pass before touching a cache file.
        }
        return null;
    }

    internal async Task WriteAsync(AgentIdentity identity, string backend, string key, long generation,
        string token, DateTimeOffset expiresAt, DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            using var access = await AcquireAccessAsync(ct).ConfigureAwait(false);
            if (!ValidateDirectory(create: true)) return;

            var path = GetPath(identity.Product);
            if (GetAttributes(path) is { } attributes && !IsRegularFile(attributes)) return;

            var payload = new CachePayload(Schema, identity.Product, identity.AgentId, identity.TenantId,
                NormalizeOrigin(backend), key, generation, token, expiresAt.ToUniversalTime(), now.ToUniversalTime());
            var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
            byte[] stored;
            try
            {
                if (bytes.Length > MaxBytes) return;
                stored = _production ? ProtectedData.Protect(bytes, Entropy(identity.Product), DataProtectionScope.LocalMachine) : bytes;
            }
            finally
            {
                if (_production) CryptographicOperations.ZeroMemory(bytes);
            }
            if (stored.Length > MaxBytes) return;

            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            var created = false;
            try
            {
                using (var stream = CreateTemporaryFile(temporary))
                {
                    created = true;
                    await stream.WriteAsync(stored, ct).ConfigureAwait(false);
                    stream.Flush(flushToDisk: true);
                }
                File.Move(temporary, path, overwrite: true);
                created = false;
            }
            finally
            {
                if (created) TryDeleteFile(temporary);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Cache availability never determines the outcome of a refresh.
        }
    }

    internal async Task InvalidateAsync(string? product, CancellationToken ct)
    {
        try
        {
            using var access = await AcquireAccessAsync(ct).ConfigureAwait(false);
            if (!ValidateDirectory(create: false)) return;
            // Keep the protected directory in place across refreshes so it cannot be squatted in the interim.
            if (product is null or AgentProducts.Cerberus)
                TryDeleteFile(GetPath(AgentProducts.Cerberus));
            if (product is null or AgentProducts.Secondary)
                TryDeleteFile(GetPath(AgentProducts.Secondary));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Invalidation is best-effort.
        }
    }

    // DpapiSecretStore already holds the publication lock when clearing active credentials.
    internal void ClearUnderActiveAccess()
    {
        try
        {
            if (!ValidateDirectory(create: false)) return;
            TryDeleteFile(GetPath(AgentProducts.Cerberus));
            TryDeleteFile(GetPath(AgentProducts.Secondary));
            if (!Directory.EnumerateFileSystemEntries(_directory).Any())
                Directory.Delete(_directory);
        }
        catch (Exception)
        {
            // Clearing active credentials must continue even if the optional cache is unavailable.
        }
    }

    private async Task<IDisposable?> AcquireAccessAsync(CancellationToken ct)
        => _canonical ? await AgentCredentialPublication.AcquireActiveAccessAsync(ct).ConfigureAwait(false) : null;

    private async Task<CachePayload?> ReadPayloadAsync(string path, string product, CancellationToken ct)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        var length = stream.Length;
        if (length is <= 0 or > MaxBytes) return null;
        var stored = new byte[(int)length];
        await stream.ReadExactlyAsync(stored, ct).ConfigureAwait(false);

        var bytes = _production ? ProtectedData.Unprotect(stored, Entropy(product), DataProtectionScope.LocalMachine) : stored;
        try
        {
            return JsonSerializer.Deserialize<CachePayload>(bytes, JsonOptions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private bool ValidateDirectory(bool create)
    {
        if (_disabled || (_production && !HasStorageAuthority())) return false;

        try
        {
            var attributes = GetAttributes(_directory);
            var directory = new DirectoryInfo(_directory);
            if (attributes is null)
            {
                if (!create) return false;
                if (_production)
                    directory.Create(CreateDirectorySecurity(_isolatedAuthority));
                else
                {
                    directory.Create();
                }
                attributes = GetAttributes(_directory);
            }

            if (attributes is { } item && item.HasFlag(FileAttributes.Directory) &&
                !item.HasFlag(FileAttributes.ReparsePoint) &&
                (!_production || HasExpectedAcl(directory.GetAccessControl())))
                return true;
        }
        catch (Exception)
        {
            // Once a path fails authority validation, leave it alone until process restart.
        }
        _disabled = true;
        return false;
    }

    private bool HasStorageAuthority()
    {
        if (_isolatedAuthority is null) return AgentUpdateSecurity.IsLocalSystem();
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User is { } user && _isolatedAuthority.Equals(user);
    }

    private static string OwnerOnlySddl(SecurityIdentifier owner) => $"O:{owner.Value}D:P(A;;FA;;;{owner.Value})";

    internal static DirectorySecurity CreateDirectorySecurity(SecurityIdentifier? isolatedAuthority = null)
    {
        var security = new DirectorySecurity();
        // ServerDataRoot inspects direct-child owner and ACL. RC is READ_CONTROL on this directory only.
        security.SetSecurityDescriptorSddlForm(OwnerOnlySddl(isolatedAuthority ?? SystemSid) + "(A;;RC;;;BA)");
        return security;
    }

    private FileStream CreateTemporaryFile(string path)
    {
        const FileOptions options = FileOptions.Asynchronous | FileOptions.WriteThrough;
        if (!_production)
            return new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, options);

        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm(OwnerOnlySddl(_isolatedAuthority ?? SystemSid));
        return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096,
            options, security);
    }

    internal bool HasExpectedAcl(FileSystemSecurity security)
    {
        var authority = _isolatedAuthority ?? SystemSid;
        var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
        if (descriptor.Owner is not { } owner || !authority.Equals(owner) ||
            !descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) ||
            descriptor.DiscretionaryAcl is not { } rules)
            return false;

        if (security is not DirectorySecurity)
            return rules.Count == 1 && IsExactAllow(rules[0], authority, FileSystemRights.FullControl);

        return rules.Count == 2 &&
            ((IsExactAllow(rules[0], authority, FileSystemRights.FullControl) &&
              IsExactAllow(rules[1], AdministratorsSid, FileSystemRights.ReadPermissions)) ||
             (IsExactAllow(rules[1], authority, FileSystemRights.FullControl) &&
              IsExactAllow(rules[0], AdministratorsSid, FileSystemRights.ReadPermissions)));
    }

    private static bool IsExactAllow(GenericAce rule, SecurityIdentifier sid, FileSystemRights rights)
        => rule is CommonAce { AceType: AceType.AccessAllowed, AceFlags: AceFlags.None } allow &&
            allow.AccessMask == (int)rights && sid.Equals(allow.SecurityIdentifier);

    private static bool IsCurrent(CachePayload payload, AgentIdentity identity, string backend, string key,
        long generation, DateTimeOffset now)
        => payload.Schema == Schema && payload.Product == identity.Product && payload.AgentId == identity.AgentId &&
            payload.TenantId == identity.TenantId && payload.Backend == NormalizeOrigin(backend) &&
            payload.KeySpkiSha256 == key && payload.LifecycleGeneration == generation &&
            !string.IsNullOrWhiteSpace(payload.AccessToken) && payload.WrittenAtUtc.Offset == TimeSpan.Zero &&
            payload.ExpiresAtUtc.Offset == TimeSpan.Zero && payload.WrittenAtUtc - now <= TimeSpan.FromMinutes(2) &&
            payload.ExpiresAtUtc > payload.WrittenAtUtc && payload.ExpiresAtUtc - payload.WrittenAtUtc <= TimeSpan.FromHours(24) &&
            payload.ExpiresAtUtc - now > TimeSpan.FromSeconds(90);

    private string GetPath(string product) => Path.Combine(_directory, product switch
    {
        AgentProducts.Cerberus => "access-token.v1.dpapi",
        AgentProducts.Secondary => "secondary-access-token.v1.dpapi",
        _ => throw new ArgumentException("Unknown agent product profile.", nameof(product)),
    });

    private static string NormalizeOrigin(string backend)
        => new Uri(backend, UriKind.Absolute).GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped);

    private static byte[] Entropy(string product) => product == AgentProducts.Secondary ? SecondaryEntropy : CerberusEntropy;

    private static FileAttributes? GetAttributes(string path)
    {
        try { return File.GetAttributes(path); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    private static bool IsRegularFile(FileAttributes attributes)
        => (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) == 0;

    private static void TryDeleteFile(string path)
    {
        try
        {
            // File.Delete unlinks a file symlink without touching its target.
            if (GetAttributes(path) is { } attributes && !attributes.HasFlag(FileAttributes.Directory))
                File.Delete(path);
        }
        catch (Exception)
        {
            // The entry can only be reused if every validation passes on a later read.
        }
    }

    internal sealed record CachedAccessToken(string Token, DateTimeOffset ExpiresAtUtc);

    private sealed record CachePayload(string Schema, string Product, string AgentId, string TenantId, string Backend,
        string KeySpkiSha256, long LifecycleGeneration, string AccessToken, DateTimeOffset ExpiresAtUtc, DateTimeOffset WrittenAtUtc);
}
