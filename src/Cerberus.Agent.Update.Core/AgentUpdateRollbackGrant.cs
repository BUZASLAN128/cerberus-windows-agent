using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Core;

internal sealed record AgentUpdateRollbackGrantRecord(string Schema, Guid GrantId, string RollbackAttemptId,
    string WatchedAttemptId, Guid ReplacedProductCode, Guid TargetProductCode, string TargetVersion,
    string TargetMsiSha256, DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc, string IssuedBootId);

public sealed record AgentUpdateRollbackGrantResult(string Result, string ReasonCode)
{
    internal static AgentUpdateRollbackGrantResult Accepted { get; } = new("admitted", "grant_accepted");
    public static AgentUpdateRollbackGrantResult Denied(string reason) => new("denied", reason);
    public bool Allowed => Result == "admitted";
}

/// <summary>MSI admission for a single SYSTEM-owned grant. No installer is launched here.</summary>
public static class AgentUpdateRollbackGrant
{
    internal const string Schema = "agent.update.rollback_grant.v1";
    internal const string FileName = "rollback-grant.json";
    internal const string Descriptor = "O:SYG:SYD:P(A;;FA;;;SY)";
    private const uint GenericReadAndDelete = 0x80010000;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint FileDispositionInfo = 4;

    [SupportedOSPlatform("windows")]
    public static AgentUpdateRollbackGrantResult Consume(string root, bool serverProfile, Guid productCode, string version,
        string detectedNewerProducts, string attemptId, string originalDatabase)
    {
        if (!serverProfile || !AgentUpdateSecurity.IsLocalSystem()) return AgentUpdateRollbackGrantResult.Denied("grant_profile");
        var store = new AgentUpdateLkgStore(root);
        var grantPath = Path.Combine(store.Root, FileName);
        var reason = "grant_path";
        try
        {
            AgentUpdateSecurity.ValidateProtectedPath(grantPath, root, allowMissing: false);
            using var handle = CreateFile(grantPath, GenericReadAndDelete, 0, IntPtr.Zero, OpenExisting, OpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid) return AgentUpdateRollbackGrantResult.Denied(reason);
            using var grantStream = new FileStream(handle, FileAccess.Read);
            if (!HasRequiredDescriptor(new RawSecurityDescriptor(grantStream.GetAccessControl().GetSecurityDescriptorBinaryForm(), 0)))
                return AgentUpdateRollbackGrantResult.Denied(reason);

            reason = "grant_parse";
            if (grantStream.Length is <= 0 or > 8192) return AgentUpdateRollbackGrantResult.Denied(reason);
            var grant = JsonSerializer.Deserialize<AgentUpdateRollbackGrantRecord>(grantStream, AgentUpdateLkgStore.RecordJson);
            return ValidateAndConsume(grant, productCode, version, detectedNewerProducts, attemptId, DateTimeOffset.UtcNow,
                AgentUpdateBootIdentity.Read, HashCanonicalMsi, () => AgentUpdateRollbackFloor.Read(root), DeleteOpenedGrant);

            string? HashCanonicalMsi()
            {
                if (!string.Equals(originalDatabase, store.MsiPath, StringComparison.OrdinalIgnoreCase))
                    return null;
                AgentUpdateSecurity.ValidateProtectedPath(store.MsiPath, root, allowMissing: false);
                using var msi = new FileStream(store.MsiPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                return Convert.ToHexString(SHA256.HashData(msi));
            }

            bool DeleteOpenedGrant()
            {
                byte delete = 1;
                return SetFileInformationByHandle(handle, FileDispositionInfo, ref delete, 1);
            }
        }
        catch (Exception ex) when (IsStorageFailure(ex))
        {
            return AgentUpdateRollbackGrantResult.Denied(reason);
        }
    }

    internal static AgentUpdateRollbackGrantResult ValidateAndConsume(AgentUpdateRollbackGrantRecord? grant,
        Guid productCode, string version, string detectedNewerProducts, string attemptId, DateTimeOffset now,
        Func<string> readBootId, Func<string?> hashCanonicalMsi, Func<AgentUpdateRollbackFloorRecord?> readFloor, Func<bool> consume)
    {
        if (grant is null || grant.Schema != Schema || grant.GrantId == Guid.Empty ||
            !AgentUpdateSecurity.IsSafeAttemptId(grant.RollbackAttemptId) || !AgentUpdateSecurity.IsSafeAttemptId(grant.WatchedAttemptId) ||
            grant.ReplacedProductCode == Guid.Empty || grant.TargetProductCode == Guid.Empty ||
            grant.ReplacedProductCode == grant.TargetProductCode || !AgentUpdateManifestValidator.IsReleaseVersion(grant.TargetVersion) ||
            !AgentUpdateManifestValidator.IsSha256(grant.TargetMsiSha256) ||
            !Guid.TryParseExact(grant.IssuedBootId, "N", out var bootId) || bootId == Guid.Empty ||
            grant.IssuedUtc == default || grant.ExpiresUtc == default || grant.IssuedUtc.Offset != TimeSpan.Zero ||
            grant.ExpiresUtc.Offset != TimeSpan.Zero)
            return AgentUpdateRollbackGrantResult.Denied("grant_schema");

        if (grant.IssuedUtc > now || grant.ExpiresUtc <= now || grant.ExpiresUtc - grant.IssuedUtc > TimeSpan.FromHours(1))
            return AgentUpdateRollbackGrantResult.Denied("grant_expired");
        var reason = "grant_boot_id";
        try
        {
            if (!string.Equals(grant.IssuedBootId, readBootId(), StringComparison.OrdinalIgnoreCase))
                return AgentUpdateRollbackGrantResult.Denied(reason);
            if (!string.Equals(grant.TargetVersion, version, StringComparison.Ordinal))
                return AgentUpdateRollbackGrantResult.Denied("grant_version");
            if (grant.TargetProductCode != productCode || !detectedNewerProducts.Split(';').Any(code =>
                    Guid.TryParse(code, out var parsed) && parsed == grant.ReplacedProductCode))
                return AgentUpdateRollbackGrantResult.Denied("grant_product_code");
            if (!string.Equals(grant.RollbackAttemptId, attemptId, StringComparison.Ordinal))
                return AgentUpdateRollbackGrantResult.Denied("grant_attempt_id");

            reason = "grant_msi_hash";
            if (!string.Equals(hashCanonicalMsi(), grant.TargetMsiSha256, StringComparison.OrdinalIgnoreCase))
                return AgentUpdateRollbackGrantResult.Denied(reason);
            reason = "grant_floor";
            if (readFloor() is not { } floor || AgentVersionComparer.CompareReleaseCore(version, floor.MinVersion) is not >= 0)
                return AgentUpdateRollbackGrantResult.Denied(reason);
            reason = "grant_consume";
            return consume() ? AgentUpdateRollbackGrantResult.Accepted : AgentUpdateRollbackGrantResult.Denied(reason);
        }
        catch (Exception ex) when (IsStorageFailure(ex))
        {
            return AgentUpdateRollbackGrantResult.Denied(reason);
        }
    }

    public static void WriteResult(string root, Guid productCode, AgentUpdateRollbackGrantResult result, DateTimeOffset now)
    {
        var transactions = Path.Combine(root, "installer-transactions");
        AgentUpdateSecurity.EnsureProtectedRoot(transactions);
        WriteResultRecord(root, transactions, productCode, result, now);
    }

    internal static void WriteResultRecord(string root, string transactions, Guid productCode,
        AgentUpdateRollbackGrantResult result, DateTimeOffset now)
        => AgentUpdateLkgStore.WriteRecord(Path.Combine(transactions, productCode.ToString("N") + ".rollback-grant.json"), root,
            new { result = result.Result, reason_code = result.ReasonCode, utc = now });

    [SupportedOSPlatform("windows")]
    internal static bool HasRequiredDescriptor(RawSecurityDescriptor descriptor)
        => descriptor.Owner?.Value == "S-1-5-18" &&
           (descriptor.ControlFlags & (ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected)) ==
               (ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected) &&
           descriptor.DiscretionaryAcl is { Count: 1 } acl && acl[0] is CommonAce ace &&
           ace.AceType == AceType.AccessAllowed && ace.AceFlags == AceFlags.None &&
           ace.SecurityIdentifier.Value == "S-1-5-18" && ace.AccessMask == 0x1F01FF;

    internal static bool IsStorageFailure(Exception ex)
        => ex is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException or ArgumentException;

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint shareMode, IntPtr securityAttributes,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, uint informationClass, ref byte information, uint size);
}
