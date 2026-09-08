using System.Runtime.CompilerServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;

[assembly: InternalsVisibleTo("Cerberus.Agent.Core.Tests")]

namespace Cerberus.Agent.Security;

/// <summary>
/// Crash recovery for the one machine-enrollment publication. Only encrypted
/// DPAPI bytes are copied; the metadata journal binds their hashes to the
/// lifecycle nonce. Lock order is launch fence, lifecycle CAS, publication.
/// Ordinary machine access takes only the last lock and rejects an unresolved
/// journal; it never tries to repair state or reenter the other locks.
/// </summary>
public sealed class AgentCredentialPublication
{
    private const int MaximumCiphertextBytes = 128 * 1024;
    private const string JournalSchema = "agent.credential-publication.v1";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 4,
    };
    private readonly string _directory;
    private readonly string _activePath;
    private readonly bool _production;
    private string JournalPath => Path.Combine(_directory, "credential-publication.json");
    private string BackupPath => Path.Combine(_directory, "prior-active.dpapi");
    private string CandidatePath => Path.Combine(_directory, "Pending", "secrets.json");
    private string PromotionMarkerPath => Path.Combine(_directory, "enrollment-adoption.json");

    public static string ProvisioningDirectory => Path.Combine(Path.GetDirectoryName(DurableAgentLifecycleStateStore.GetDefaultPath())!, "Provisioning");
    public static string PendingDirectory => Path.Combine(ProvisioningDirectory, "Pending");
    public static string MarkerPath => Path.Combine(ProvisioningDirectory, "enrollment-adoption.json");
    public static bool RecoveryRequired => Production.ExistsValidated(Production.JournalPath);
    private static AgentCredentialPublication Production => new(ProvisioningDirectory,
        DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.Machine), production: true);

    private AgentCredentialPublication(string directory, string activePath, bool production)
        => (_directory, _activePath, _production) = (directory, activePath, production);

    // Explicit isolated file-system oracle. Custom DpapiSecretStore paths do not
    // acquire production hooks or silently opt into machine authority.
    internal AgentCredentialPublication(string directory, string activePath)
        : this(Path.GetFullPath(directory), Path.GetFullPath(activePath), production: false) { }

    public static void EnsureProvisioningDirectory()
    {
        RequireElevated();
        if (!Directory.Exists(ProvisioningDirectory))
            AgentUpdateSecurity.EnsureProtectedRoot(ProvisioningDirectory);
        AgentUpdateSecurity.ValidateProtectedPath(ProvisioningDirectory, ProvisioningDirectory, allowMissing: false);
    }

    public static void ValidateProtectedItem(string path, bool allowMissing = false)
    {
        AgentUpdateSecurity.ValidateProtectedPath(path, ProvisioningDirectory, allowMissing);
        if (File.Exists(path)) ValidatePrivateAcl(path);
    }

    public static void EnsurePendingDirectory()
    {
        EnsureProvisioningDirectory();
        if (!Directory.Exists(PendingDirectory))
            AgentUpdateSecurity.EnsureProtectedRoot(PendingDirectory);
        ValidateProtectedItem(PendingDirectory);
    }

    public static Task PublishPromotionMarkerAsync(byte[] metadata, CancellationToken ct)
    {
        RequireNoUnresolvedPublication();
        if (metadata.Length is <= 0 or > 4096)
            throw new InvalidDataException("Enrollment marker exceeds its bounds.");
        return Production.WriteAtomicAsync(MarkerPath, metadata, ct);
    }

    /// <summary>Fail-closed gate used only by the canonical machine DPAPI store.</summary>
    public static Task<IDisposable> AcquireActiveAccessAsync(CancellationToken ct)
        => Production.AcquireResolvedAccessAsync(ct);

    internal async Task<IDisposable> AcquireResolvedAccessAsync(CancellationToken ct)
    {
        var gate = await AcquirePublicationLockAsync(ct).ConfigureAwait(false);
        try
        {
            if (ExistsValidated(JournalPath))
                throw new InvalidOperationException("Machine credential adoption requires service recovery.");
            ValidateItem(_activePath, allowMissing: true);
            return gate;
        }
        catch { gate.Dispose(); throw; }
    }

    /// <summary>Elevated setup may stage credentials, but may not repair an interrupted service commit.</summary>
    public static void RequireNoUnresolvedPublication()
    {
        EnsureProvisioningDirectory();
        if (Production.ExistsValidated(Production.JournalPath))
            throw new InvalidOperationException("Machine credential adoption requires service recovery.");
    }

    public static async Task RecoverAsync(DurableAgentLifecycleStateStore lifecycle, CancellationToken ct)
    {
        if (!AgentUpdateSecurity.IsLocalSystem())
            throw new UnauthorizedAccessException("Only the service can recover machine credential publication.");
        using var fence = await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false);
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var snapshot = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
            if (await lifecycle.ExecuteIfCurrentAsync(snapshot.Generation,
                cancel => Production.RecoverWithLockAsync(snapshot, cancel), ct).ConfigureAwait(false))
                return;
        }
        throw new InvalidOperationException("Lifecycle changed during credential recovery.");
    }

    internal async Task RecoverWithLockAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct)
    {
        using var gate = await AcquirePublicationLockAsync(ct).ConfigureAwait(false);
        await ReconcileLockedAsync(snapshot, ct).ConfigureAwait(false);
    }

    /// <summary>Caller already holds the launch fence and lifecycle CAS lock.</summary>
    public static Task<IAsyncDisposable> BeginAsync(DurableAgentLifecycleStateStore lifecycle,
        long expectedGeneration, string nonce, CancellationToken ct)
    {
        if (!AgentUpdateSecurity.IsLocalSystem())
            throw new UnauthorizedAccessException("Only the service can publish machine credentials.");
        return Production.BeginLockedAsync(expectedGeneration, nonce, lifecycle.LoadAsync, ct);
    }

    internal async Task<IAsyncDisposable> BeginLockedAsync(long expectedGeneration, string nonce,
        Func<CancellationToken, Task<AgentLifecycleSnapshot>> loadLifecycle, CancellationToken ct)
    {
        if (expectedGeneration < 0 || !Guid.TryParseExact(nonce, "N", out _))
            throw new InvalidDataException("Invalid credential publication binding.");
        var gate = await AcquirePublicationLockAsync(ct).ConfigureAwait(false);
        try
        {
            if (ExistsValidated(JournalPath))
                throw new InvalidOperationException("Previous credential publication requires recovery.");
            var next = await ReadBoundedAsync(CandidatePath, MaximumCiphertextBytes, ct).ConfigureAwait(false);
            var prior = ExistsValidated(_activePath)
                ? await ReadBoundedAsync(_activePath, MaximumCiphertextBytes, ct).ConfigureAwait(false) : null;
            // A crash before journal publication cannot have changed active.
            if (prior is not null)
                await WriteAtomicAsync(BackupPath, prior, ct).ConfigureAwait(false);
            else
                DeleteValidated(BackupPath);
            var journal = new PublicationJournal(JournalSchema, expectedGeneration, nonce,
                prior is null ? null : Digest(prior), Digest(next));
            await WriteAtomicAsync(JournalPath, JsonSerializer.SerializeToUtf8Bytes(journal, JsonOptions), ct).ConfigureAwait(false);
            await WriteAtomicAsync(_activePath, next, ct).ConfigureAwait(false);
            // Keep the publication lock held through the lifecycle nonce write.
            return new PublicationLease(this, gate, loadLifecycle);
        }
        catch
        {
            try
            {
                using var recovery = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await ReconcileLockedAsync(await loadLifecycle(recovery.Token).ConfigureAwait(false), recovery.Token).ConfigureAwait(false);
            }
            finally { gate.Dispose(); }
            throw;
        }
    }

    private async Task ReconcileLockedAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct)
    {
        if (!ExistsValidated(JournalPath))
        {
            DeleteValidated(BackupPath); // interrupted prepare, active was never published
            return;
        }
        var bytes = await ReadBoundedAsync(JournalPath, 4096, ct).ConfigureAwait(false);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            document.RootElement.EnumerateObject().GroupBy(p => p.Name, StringComparer.Ordinal).Any(g => g.Count() != 1))
            throw new InvalidDataException("Credential publication journal is invalid.");
        var journal = JsonSerializer.Deserialize<PublicationJournal>(bytes, JsonOptions);
        if (journal is null || journal.SchemaVersion != JournalSchema || journal.ExpectedGeneration < 0 ||
            !Guid.TryParseExact(journal.Nonce, "N", out _) || !IsDigest(journal.NextCiphertextSha256) ||
            (journal.PriorCiphertextSha256 is not null && !IsDigest(journal.PriorCiphertextSha256)) ||
            snapshot.ReasonCode == "lifecycle_state_invalid")
            throw new InvalidDataException("Credential publication journal is invalid.");
        var active = ExistsValidated(_activePath)
            ? await ReadBoundedAsync(_activePath, MaximumCiphertextBytes, ct).ConfigureAwait(false) : null;
        var activeDigest = active is null ? null : Digest(active);
        var committed = snapshot.LastEnrollmentNonce == journal.Nonce && snapshot.Generation > journal.ExpectedGeneration;
        if (committed)
        {
            if (activeDigest != journal.NextCiphertextSha256)
                throw new InvalidDataException("Committed machine credential binding is inconsistent.");
            if (ExistsValidated(PromotionMarkerPath))
            {
                var markerBytes = await ReadBoundedAsync(PromotionMarkerPath, 4096, ct).ConfigureAwait(false);
                using var marker = JsonDocument.Parse(markerBytes, new JsonDocumentOptions { MaxDepth = 4 });
                if (marker.RootElement.ValueKind != JsonValueKind.Object ||
                    marker.RootElement.EnumerateObject().Count(p => p.Name == "nonce") != 1 ||
                    !marker.RootElement.TryGetProperty("nonce", out var nonce) || nonce.ValueKind != JsonValueKind.String ||
                    nonce.GetString() != journal.Nonce)
                    throw new InvalidDataException("Committed enrollment marker binding is inconsistent.");
            }
            // No new staging is allowed while this journal exists. Cleanup is
            // idempotent if the process stopped halfway through these deletes.
            DeleteValidated(CandidatePath);
            DeleteValidated(PromotionMarkerPath);
        }
        else
        {
            if (snapshot.Generation != journal.ExpectedGeneration || snapshot.LastEnrollmentNonce == journal.Nonce ||
                (activeDigest != journal.NextCiphertextSha256 && activeDigest != journal.PriorCiphertextSha256))
                throw new InvalidDataException("Uncommitted machine credential binding is stale.");
            if (journal.PriorCiphertextSha256 is not null && activeDigest != journal.PriorCiphertextSha256)
            {
                var prior = await ReadBoundedAsync(BackupPath, MaximumCiphertextBytes, ct).ConfigureAwait(false);
                if (Digest(prior) != journal.PriorCiphertextSha256)
                    throw new InvalidDataException("Machine credential rollback binding is inconsistent.");
                await WriteAtomicAsync(_activePath, prior, ct).ConfigureAwait(false);
            }
            else if (journal.PriorCiphertextSha256 is null)
                DeleteValidated(_activePath);
        }
        // Journal is removed last: any earlier failure keeps all readers closed.
        DeleteValidated(BackupPath);
        DeleteValidated(JournalPath);
    }

    private async Task<FileStream> AcquirePublicationLockAsync(CancellationToken ct)
    {
        if (_production) EnsureProvisioningDirectory();
        else Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "credential-publication.lock");
        var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            ValidateItem(path, allowMissing: true);
            try
            {
                return File.Exists(path)
                    ? new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None)
                    : CreatePrivateFile(path);
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(25, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task<byte[]> ReadBoundedAsync(string path, int maximum, CancellationToken ct)
    {
        ValidateItem(path, allowMissing: false);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 || stream.Length > maximum)
            throw new InvalidDataException("Credential transaction record exceeds its bounds.");
        var bytes = new byte[(int)stream.Length];
        await stream.ReadExactlyAsync(bytes, ct).ConfigureAwait(false);
        return bytes;
    }

    private async Task WriteAtomicAsync(string path, byte[] bytes, CancellationToken ct)
    {
        ValidateItem(path, allowMissing: true);
        var temporary = path + ".publication-new";
        DeleteValidated(temporary);
        try
        {
            await using (var stream = CreatePrivateFile(temporary))
            {
                await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
                stream.Flush(true);
            }
            ct.ThrowIfCancellationRequested();
            ValidateItem(path, allowMissing: true);
            File.Move(temporary, path, overwrite: true);
        }
        finally { DeleteValidated(temporary); }
    }

    private FileStream CreatePrivateFile(string path)
    {
        if (!_production)
            return new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
        return CreateProtectedFile(path);
    }

    internal static FileStream CreateProtectedFile(string path)
    {
        RequireElevated();
        var acl = new FileSecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(new SecurityIdentifier(AgentUpdateSecurity.IsLocalSystem()
            ? WellKnownSidType.LocalSystemSid : WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        // DACL is applied at creation, before even an empty handle can be opened
        // by a standard user in the legacy product directory.
        return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough, acl);
    }

    private bool ExistsValidated(string path)
    {
        ValidateItem(path, allowMissing: true);
        try { return !File.GetAttributes(path).HasFlag(FileAttributes.Directory); }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    private void DeleteValidated(string path)
    {
        if (ExistsValidated(path)) File.Delete(path);
    }

    private void ValidateItem(string path, bool allowMissing)
    {
        if (_production)
        {
            var root = AgentUpdateSecurity.IsUnderDirectory(path, _directory) ? _directory : Path.GetDirectoryName(_activePath)!;
            AgentUpdateSecurity.ValidateProtectedPath(path, root, allowMissing);
            if (File.Exists(path)) ValidatePrivateAcl(path);
        }
        else
        {
            if (!AgentUpdateSecurity.IsUnderDirectory(path, _directory) &&
                path != _activePath && path != _activePath + ".publication-new")
                throw new UnauthorizedAccessException("Isolated credential path escaped its test boundary.");
            if (File.Exists(path) && File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
                throw new UnauthorizedAccessException("Credential transaction path is untrusted.");
        }
    }

    private static void ValidatePrivateAcl(string path)
    {
        var security = new FileInfo(path).GetAccessControl();
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new UnauthorizedAccessException("Credential transaction owner is unavailable.");
        if (!owner.IsWellKnown(WellKnownSidType.LocalSystemSid) && !owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            throw new UnauthorizedAccessException("Credential transaction owner is untrusted.");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (!sid.IsWellKnown(WellKnownSidType.LocalSystemSid) && !sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                throw new UnauthorizedAccessException("Credential transaction read access is untrusted.");
        }
    }

    private static void RequireElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Machine credential storage requires elevated authority.");
    }

    private static string Digest(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    private static bool IsDigest(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    private sealed record PublicationJournal(string SchemaVersion, long ExpectedGeneration, string Nonce,
        string? PriorCiphertextSha256, string NextCiphertextSha256);

    private sealed class PublicationLease(AgentCredentialPublication owner, FileStream gate,
        Func<CancellationToken, Task<AgentLifecycleSnapshot>> loadLifecycle) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            try
            {
                // Caller cancellation after publication must not skip rollback.
                using var recovery = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await owner.ReconcileLockedAsync(await loadLifecycle(recovery.Token).ConfigureAwait(false), recovery.Token).ConfigureAwait(false);
            }
            finally { gate.Dispose(); }
        }
    }
}
