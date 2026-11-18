using System.IO;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static partial class AgentUpdateLabRuntimeAdmission
{
    internal sealed record RollbackAdmissionGrant(string CampaignId, string TransactionId, string PolicySha256,
        AgentStateDeliveryContext Identity, string AttemptId, string RollbackAttemptId, string SourceVersion,
        string Version, string ArtifactSha256, DateTimeOffset AdmittedUtc, DateTimeOffset ExpiresUtc);

    internal sealed record VersionReceipt(string Version, string UpdaterSha256, string? MsiArtifactSha256,
        string TransactionId, DateTimeOffset Utc);

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    internal sealed record SkippedRelease(string CampaignId, string Version, string AttemptId, string RestoredVersion,
        DateTimeOffset Utc);

    internal static void AdmitRollback(AgentUpdateLabPolicy policy, AgentStateDeliveryContext identity,
        string rollbackAttemptId, string targetVersion, string msiSha256, string transactionId)
    {
        var compiled = Policy();
        if (compiled is null) return;
        if (!AgentUpdateSecurity.IsLocalSystem() || compiled.CampaignId != policy.CampaignId ||
            !IsTransactionId(transactionId) || ReadIdentity(requireActive: true) != identity)
            throw new InvalidOperationException("Development rollback launch authority is invalid.");
        var source = ReadInstalledSourceVersion();
        var root = Root(compiled);
        using var held = Lock(root);
        var journal = new AgentUpdateJournalStore(AgentUpdateStager.DefaultStagingRoot).Read();
        var now = DateTimeOffset.UtcNow;
        RequireRollbackContext(journal, compiled, identity, rollbackAttemptId, source, targetVersion, now);
        var forward = ReadVersionAdmission(root, compiled, identity, targetVersion);
        if (forward is null || !MatchesHash(forward.ArtifactSha256, msiSha256))
            throw new InvalidOperationException("Development rollback MSI does not match the completed forward admission.");
        var path = RollbackPath(root, transactionId);
        if (AgentUpdateDurableFile.Read<RollbackAdmissionGrant>(path, root) is not null ||
            AgentUpdateDurableFile.Read<LaunchGrant>(LaunchPath(root, transactionId), root) is not null)
            throw new InvalidOperationException("Development rollback transaction identity cannot be reused.");
        RequireUnusedAdmission(root, transactionId);
        var maximum = now.AddHours(1);
        AgentUpdateDurableFile.Write(path, root, new RollbackAdmissionGrant(compiled.CampaignId, transactionId,
            PolicyHash(), identity, journal.AttemptId!, rollbackAttemptId, source, targetVersion, msiSha256,
            now, compiled.ExpiresAtUtc < maximum ? compiled.ExpiresAtUtc : maximum));
    }

    internal static Admission RequireRollbackBegin(RollbackAdmissionGrant? grant, Admission? forward,
        AgentUpdateJournal journal, AgentUpdateLabPolicy policy, AgentStateDeliveryContext identity, Guid productCode,
        string version, string source, string transactionId, string policyHash, string runtimeHashes, DateTimeOffset now)
    {
        if (grant is null || grant.CampaignId != policy.CampaignId || grant.TransactionId != transactionId ||
            !IsTransactionId(transactionId) || grant.Identity != identity || grant.PolicySha256 != policyHash ||
            grant.Version != version || grant.SourceVersion != source || grant.AttemptId != journal.AttemptId ||
            grant.AdmittedUtc < policy.NotBeforeUtc || grant.AdmittedUtc > now || now >= grant.ExpiresUtc ||
            grant.ExpiresUtc > policy.ExpiresAtUtc || grant.ExpiresUtc - grant.AdmittedUtc > TimeSpan.FromHours(1))
            throw new InvalidOperationException("Development rollback transaction has no matching admission.");
        RequireRollbackContext(journal, policy, identity, grant.RollbackAttemptId, source, version, now);
        if (forward is not { Completed: true, Kind: "forward" } || forward.Version != version ||
            forward.CampaignId != policy.CampaignId || forward.PolicySha256 != policyHash || forward.Identity != identity ||
            forward.ProductCode != productCode.ToString("D") || forward.RuntimeHashesBase64 != runtimeHashes ||
            !MatchesHash(forward.ArtifactSha256, grant.ArtifactSha256))
            throw new InvalidOperationException("Development rollback payload differs from the admitted predecessor.");
        return new Admission(policy.CampaignId, transactionId, productCode.ToString("D"), version, policyHash,
            runtimeHashes, identity, grant.AdmittedUtc, grant.AttemptId, grant.ArtifactSha256, SourceVersion: source, Kind: "rollback");
    }

    private static void RequireRollbackContext(AgentUpdateJournal journal, AgentUpdateLabPolicy policy,
        AgentStateDeliveryContext identity, string rollbackAttemptId, string source, string target, DateTimeOffset now)
    {
        policy.RequireTarget(new(identity.AgentId, identity.TenantId, identity.Product), identity.KeyFingerprint, now);
        AgentUpdateCampaignTransition.RequireNext(policy.Versions, target, source);
        if (journal.Phase != "rolling_back" || !AgentUpdateSecurity.IsSafeAttemptId(rollbackAttemptId) ||
            journal.RollbackAttemptId != rollbackAttemptId || !AgentUpdateSecurity.IsSafeAttemptId(journal.AttemptId) ||
            journal.LifecycleGeneration != identity.Generation || journal.InstallRequest is not { } request ||
            request.LocalPolicyId != policy.CampaignId || request.LifecycleGeneration != identity.Generation ||
            request.BoundAttemptId != journal.AttemptId || request.VerifiedRelease is not { } release || release.Version != source ||
            request.ExpectedPlan is not { } expected || !expected.Matches(release))
            throw new InvalidOperationException("Development rollback no longer matches the active campaign attempt.");
    }

    internal static void WriteVersionReceipt(string root, Admission admission, DateTimeOffset now)
    {
        var path = VersionPath(root, admission.Version);
        // A rollback keeps the predecessor's original receipt and transaction. A disagreement stays visible to readers.
        if (AgentUpdateDurableFile.Read<VersionReceipt>(path, root) is not null) return;
        var updaterSha256 = ParseHashes(admission.RuntimeHashesBase64)["Cerberus.Agent.Updater.exe"];
        AgentUpdateDurableFile.Write(path, root, new VersionReceipt(admission.Version, updaterSha256,
            admission.ArtifactSha256, admission.TransactionId, now));
    }

    internal static bool IsAdmittedLabArtifact(string kind, string version, string sha256)
    {
        if (!IsCompiled || !AgentUpdateSecurity.IsLocalSystem()) return false;
        try
        {
            var policy = Policy();
            return policy is not null && IsAdmittedLabArtifact(policy, ReadIdentity(requireActive: false), kind, version, sha256);
        }
        catch (Exception ex) when (IsLabRecordFailure(ex)) { return false; }
    }

    internal static bool IsAdmittedLabArtifact(AgentUpdateLabPolicy policy, AgentStateDeliveryContext identity,
        string kind, string version, string sha256)
    {
        if (!IsCompiled || !AgentUpdateSecurity.IsLocalSystem() || kind is not ("updater" or "msi") ||
            !policy.Versions.Contains(version, StringComparer.Ordinal)) return false;
        var admission = ReadVersionAdmission(TransactionRoot(policy), policy, identity, version);
        return admission is not null && (kind == "msi"
            ? MatchesHash(admission.ArtifactSha256, sha256)
            : MatchesHash(ParseHashes(admission.RuntimeHashesBase64)["Cerberus.Agent.Updater.exe"], sha256));
    }

    internal static bool MatchesVersionReceipt(VersionReceipt receipt, Admission admission, AgentUpdateLabPolicy policy,
        AgentStateDeliveryContext identity, string version, string policyHash)
        => admission.Completed && admission.Kind == "forward" && admission.CampaignId == policy.CampaignId &&
            admission.PolicySha256 == policyHash && admission.Identity == identity && admission.Version == version &&
            receipt.Version == version && receipt.TransactionId == admission.TransactionId &&
            (receipt.MsiArtifactSha256 is null && admission.ArtifactSha256 is null ||
             MatchesHash(receipt.MsiArtifactSha256, admission.ArtifactSha256)) &&
            MatchesHash(receipt.UpdaterSha256, ParseHashes(admission.RuntimeHashesBase64)["Cerberus.Agent.Updater.exe"]);

    private static Admission? ReadVersionAdmission(string root, AgentUpdateLabPolicy policy,
        AgentStateDeliveryContext identity, string version)
    {
        var receipt = AgentUpdateDurableFile.Read<VersionReceipt>(VersionPath(root, version), root);
        if (receipt is null || !IsTransactionId(receipt.TransactionId)) return null;
        var admission = AgentUpdateDurableFile.Read<Admission>(ReceiptPath(root, receipt.TransactionId), root);
        return admission is not null && MatchesVersionReceipt(receipt, admission, policy, identity, version, PolicyHash())
            ? admission : null;
    }

    internal static bool IsLabRecordFailure(Exception ex) => ex is InvalidOperationException or UnauthorizedAccessException
        or IOException or System.Text.Json.JsonException or FormatException or System.Security.Cryptography.CryptographicException;

    private static bool MatchesHash(string? left, string? right) => left is { Length: 64 } && left.All(Uri.IsHexDigit) &&
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    private static bool IsTransactionId(string? transactionId) =>
        Guid.TryParseExact(transactionId, "D", out var parsed) && parsed != Guid.Empty;

    internal static void RequireUnusedAdmission(string root, string transactionId)
    {
        if (!IsTransactionId(transactionId) || AgentUpdateDurableFile.Read<Admission>(ReceiptPath(root, transactionId), root) is not null)
            throw new InvalidOperationException("Development MSI transaction admission cannot be reused.");
    }

    private static string RollbackPath(string root, string transactionId) => Path.Combine(root, transactionId + ".rollback.json");
    private static string VersionPath(string root, string version) => Path.Combine(root, "updater-" + version + ".json");
    private static string TransactionRoot(AgentUpdateLabPolicy policy) => Path.Combine(CampaignRoot(policy), "installer-transactions");
    internal static string CampaignRoot(AgentUpdateLabPolicy policy) =>
        Path.Combine(AgentUpdateStager.DefaultStagingRoot, "lab-campaign-" + policy.CampaignId);

    internal static SkippedRelease? ReadSkipped(AgentUpdateLabPolicy policy)
    {
        var root = CampaignRoot(policy);
        var skip = AgentUpdateDurableFile.Read<SkippedRelease>(Path.Combine(root, "skipped.json"), root);
        if (skip is not null && (skip.CampaignId != policy.CampaignId || skip.Version != policy.Versions[5] ||
            skip.RestoredVersion != policy.Versions[4] || !AgentUpdateSecurity.IsSafeAttemptId(skip.AttemptId) ||
            skip.Utc.Offset != TimeSpan.Zero || skip.Utc < policy.NotBeforeUtc || skip.Utc >= policy.ExpiresAtUtc))
            throw new InvalidOperationException("Development campaign skip record is invalid.");
        return skip;
    }

    internal static IReadOnlyList<string> ReadEffectiveVersions(AgentUpdateLabPolicy policy) =>
        EffectiveVersions(policy, ReadSkipped(policy));

    internal static IReadOnlyList<string> EffectiveVersions(AgentUpdateLabPolicy policy, SkippedRelease? skip) =>
        skip is null ? policy.Versions : policy.Versions.Where(version => version != skip.Version).ToArray();
}
