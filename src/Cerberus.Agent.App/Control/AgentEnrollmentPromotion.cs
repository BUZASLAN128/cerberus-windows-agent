using System.IO;
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
    private static string MarkerPath => AgentCredentialPublication.MarkerPath;

    internal static ISecretStore OpenPendingStore()
    {
        AgentCredentialPublication.EnsurePendingDirectory();
        return new DpapiSecretStore(SecretStoreScope.Machine, AgentCredentialPublication.PendingDirectory);
    }

    internal static ISecretStore OpenProbeStore(AgentEnrollmentMarker marker) => new PendingProbeStore(marker);

    internal static bool IsAwaitingAdoption(AgentEnrollmentMarker? marker, AgentLifecycleSnapshot state)
        => marker is not null && marker.ExpectedGeneration == state.Generation && marker.Nonce != state.LastEnrollmentNonce;

    internal static async Task WriteAsync(long generation, ISecretStore promoted, CancellationToken ct)
    {
        RequireElevated();
        EnsureDirectory();
        AgentCredentialPublication.RequireNoUnresolvedPublication();
        AgentCredentialPublication.ValidateProtectedItem(MarkerPath, allowMissing: true);
        var (identity, _, key, _, _, _) = await promoted.LoadAsync(ct).ConfigureAwait(false);
        var marker = new AgentEnrollmentMarker(Schema, generation, identity.AgentId, identity.TenantId,
            PublicKeyDigest(key), Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow.AddMinutes(5));
        await AgentCredentialPublication.PublishPromotionMarkerAsync(JsonSerializer.SerializeToUtf8Bytes(marker, Options), ct).ConfigureAwait(false);
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

    private static string PublicKeyDigest(string privateKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKey);
        return Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
    }

    private static void RequireSafeFile()
        => AgentCredentialPublication.ValidateProtectedItem(MarkerPath);

    private static void EnsureDirectory()
    {
        AgentCredentialPublication.EnsureProvisioningDirectory();
    }

    private static void RequireElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Enrollment promotion requires elevated authority.");
    }

    private sealed class PendingProbeStore(AgentEnrollmentMarker marker) : ISecretStore
    {
        public async Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            using var fence = await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false);
            await RequireCurrentAsync(ct).ConfigureAwait(false);
            var store = OpenPendingStore();
            if (!await MatchesAsync(marker, store, ct).ConfigureAwait(false))
                throw new InvalidDataException("Pending enrollment identity changed.");
            return await store.LoadAsync(ct).ConfigureAwait(false);
        }

        public async Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
        {
            using var fence = await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false);
            await RequireCurrentAsync(ct).ConfigureAwait(false);
            if (identity.AgentId != marker.AgentId || identity.TenantId != marker.TenantId || PublicKeyDigest(privateKeyPem) != marker.PublicKeyDigest)
                throw new InvalidDataException("Pending enrollment identity changed.");
            // Preserve refresh rotation even when the subsequent heartbeat is
            // rejected, without publishing anything to the active machine file.
            await OpenPendingStore().SaveAsync(identity, refreshToken, privateKeyPem, backendUrl,
                tailscaleLoginServer, tailscaleAuthkey, ct).ConfigureAwait(false);
        }

        public Task ClearAsync(CancellationToken ct) => throw new InvalidOperationException("Enrollment probe cannot clear credentials.");

        private async Task RequireCurrentAsync(CancellationToken ct)
        {
            AgentCredentialPublication.RequireNoUnresolvedPublication();
            if (await ReadAsync(ct).ConfigureAwait(false) != marker)
                throw new InvalidDataException("Pending enrollment proof changed.");
        }
    }
}

/// <summary>In-memory rollback snapshot for a failed non-authoritative credential copy.</summary>
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
