using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Control;

internal sealed record AgentEnrollmentMarker(string SchemaVersion, long ExpectedGeneration, string AgentId,
    string TenantId, string PublicKeyDigest, string Nonce, DateTimeOffset ExpiresUtc);

/// <summary>Non-secret proof of the existing elevated PKCE credential promotion; never accepts a caller-selected path.</summary>
internal static class AgentEnrollmentPromotion
{
    private const string Schema = "agent.enrollment-promotion.v1";
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 4,
    };
    internal static string DirectoryPath => Path.Combine(Path.GetDirectoryName(DurableAgentLifecycleStateStore.GetDefaultPath())!, "Provisioning");
    private static string MarkerPath => Path.Combine(DirectoryPath, "enrollment-adoption.json");

    internal static async Task WriteAsync(long generation, ISecretStore promoted, CancellationToken ct)
    {
        RequireElevated();
        EnsureDirectory();
        var (identity, _, key, _, _, _) = await promoted.LoadAsync(ct).ConfigureAwait(false);
        var marker = new AgentEnrollmentMarker(Schema, generation, identity.AgentId, identity.TenantId,
            PublicKeyDigest(key), Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow.AddMinutes(5));
        var temp = MarkerPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(marker, Options), ct).ConfigureAwait(false);
                stream.Flush(true);
            }
            ct.ThrowIfCancellationRequested();
            File.Move(temp, MarkerPath, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    internal static async Task<AgentEnrollmentMarker?> ReadAsync(CancellationToken ct)
    {
        EnsureDirectory();
        if (!File.Exists(MarkerPath)) return null;
        RequireSafeFile();
        await using var stream = new FileStream(MarkerPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is <= 0 or > 4096) return null;
        var bytes = new byte[(int)stream.Length];
        await stream.ReadExactlyAsync(bytes, ct).ConfigureAwait(false);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            document.RootElement.EnumerateObject().GroupBy(property => property.Name, StringComparer.Ordinal).Any(group => group.Count() != 1))
            return null;
        var marker = JsonSerializer.Deserialize<AgentEnrollmentMarker>(bytes, Options);
        if (marker is null || marker.SchemaVersion != Schema || marker.ExpectedGeneration < 0 ||
            !Guid.TryParseExact(marker.Nonce, "N", out _) || marker.ExpiresUtc <= DateTimeOffset.UtcNow ||
            marker.ExpiresUtc > DateTimeOffset.UtcNow.AddMinutes(5) || marker.PublicKeyDigest is not { Length: 64 } ||
            string.IsNullOrWhiteSpace(marker.AgentId) || marker.AgentId.Length > 256 ||
            string.IsNullOrWhiteSpace(marker.TenantId) || marker.TenantId.Length > 256)
            return null;
        return marker;
    }

    internal static async Task<bool> MatchesAsync(AgentEnrollmentMarker marker, ISecretStore store, CancellationToken ct)
    {
        var (identity, _, key, _, _, _) = await store.LoadAsync(ct).ConfigureAwait(false);
        return marker.AgentId == identity.AgentId && marker.TenantId == identity.TenantId &&
            marker.PublicKeyDigest == PublicKeyDigest(key);
    }

    internal static void RemoveConsumed()
    {
        if (!File.Exists(MarkerPath)) return;
        RequireSafeFile();
        File.Delete(MarkerPath);
    }

    private static string PublicKeyDigest(string privateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKey);
        return Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
    }

    private static void RequireSafeFile()
    {
        if (File.GetAttributes(MarkerPath).HasFlag(FileAttributes.ReparsePoint))
            throw new UnauthorizedAccessException("Enrollment marker path is untrusted.");
        var rules = new FileInfo(MarkerPath).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (!sid.IsWellKnown(WellKnownSidType.LocalSystemSid) && !sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                throw new UnauthorizedAccessException("Enrollment marker ACL is untrusted.");
        }
    }

    private static void EnsureDirectory()
    {
        RequireElevated();
        for (var current = new DirectoryInfo(DirectoryPath); current is not null; current = current.Parent)
            if (current.Exists && current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new UnauthorizedAccessException("Enrollment directory is untrusted.");
        Directory.CreateDirectory(DirectoryPath);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(DirectoryPath).SetAccessControl(security);
    }

    private static void RequireElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Enrollment promotion requires elevated authority.");
    }
}

/// <summary>Refresh rotation is staged in memory during adoption and published only after the generation and marker checks.</summary>
internal sealed class AgentEnrollmentProbeStore : ISecretStore
{
    private (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey) _value;
    internal AgentEnrollmentProbeStore((AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey) value) => _value = value;
    public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        => Task.FromResult(_value);
    public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
    {
        _value = (identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey);
        return Task.CompletedTask;
    }
    public Task ClearAsync(CancellationToken ct) => throw new InvalidOperationException("Enrollment probe cannot clear credentials.");
    internal Task PublishAsync(ISecretStore destination, CancellationToken ct)
        => destination.SaveAsync(_value.Identity, _value.RefreshToken, _value.PrivateKeyPem, _value.BackendUrl, _value.TailscaleLoginServer, _value.TailscaleAuthkey, ct);
}
