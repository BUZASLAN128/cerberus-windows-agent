using System.Reflection;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>Shared with the MSI helper; admission precedes StopServices and cannot be renewed by a later health check.</summary>
internal static class AgentUpdateLabRuntimeAdmission
{
    internal sealed record Admission(string CampaignId, string TransactionId, string ProductCode, string Version,
        string PolicySha256, string RuntimeHashesBase64, AgentStateDeliveryContext Identity, DateTimeOffset AdmittedUtc,
        string? AttemptId, string? ArtifactSha256, bool Completed = false);
    internal sealed record LaunchGrant(string CampaignId, string TransactionId, string Version, string PolicySha256,
        AgentStateDeliveryContext Identity, DateTimeOffset AdmittedUtc, DateTimeOffset ExpiresUtc, string AttemptId, string ArtifactSha256);

    internal static void AdmitLaunch(AgentUpdateLabPolicy policy, AgentStateDeliveryContext identity,
        AgentUpdatePlan plan, AgentUpdateInstallRequest request, string transactionId)
    {
        var now = DateTimeOffset.UtcNow;
        policy.RequireTarget(new(identity.AgentId, identity.TenantId, identity.Product), identity.KeyFingerprint, now);
        policy.RequireVersion(plan.Version);
        if (!AgentUpdateSecurity.IsLocalSystem() || !Guid.TryParseExact(transactionId, "D", out _) ||
            request.LocalPolicyId != policy.CampaignId || request.ExpiresUtc <= now || request.ExpiresUtc > policy.ExpiresAtUtc ||
            request.BoundAttemptId != plan.AttemptId || request.VerifiedRelease is null ||
            !request.VerifiedRelease.Matches(AgentUpdateExpectedPlan.FromPlan(plan)))
            throw new InvalidOperationException("Development MSI launch grant is invalid.");
        var root = Root(policy);
        using var held = Lock(root);
        var path = LaunchPath(root, transactionId);
        if (File.Exists(path)) throw new InvalidOperationException("Development launch identity cannot be reused.");
        AgentUpdateDurableFile.Write(path, root, new LaunchGrant(policy.CampaignId, transactionId, plan.Version,
            PolicyHash(), identity, now, request.ExpiresUtc, plan.AttemptId!, plan.Sha256));
    }

    private static string Metadata(string name) => typeof(AgentUpdateLabRuntimeAdmission).Assembly
        .GetCustomAttributes<AssemblyMetadataAttribute>().SingleOrDefault(a => a.Key == name)?.Value ?? "";

    private static AgentUpdateLabPolicy? Policy() => AgentUpdateLabPolicy.Parse(Metadata(AgentUpdateLabPolicy.MetadataName),
        Metadata("AgentReleaseChannel"), Metadata("AllowUnsignedDevBuild") == "true", AgentBuildProfile.IsServer);

    internal static bool IsCompiled => !string.IsNullOrEmpty(Metadata(AgentUpdateLabPolicy.MetadataName));

    internal static void Begin(Guid productCode, string version, string? transactionId)
    {
        var policy = Policy();
        if (policy is null) return;
        RequireInvocation(policy, version, transactionId);
        var identity = ReadIdentity(requireActive: true);
        var now = DateTimeOffset.UtcNow;
        var journal = new AgentUpdateJournalStore(AgentUpdateStager.DefaultStagingRoot).Read();
        string? attempt = null, artifact = null;
        var root = Root(policy);
        using var held = Lock(root);
        if (version != policy.Versions[0])
        {
            var request = journal.InstallRequest;
            var grant = AgentUpdateDurableFile.Read<LaunchGrant>(LaunchPath(root, transactionId!), root)
                ?? throw new InvalidOperationException("Development updater launch admission is missing.");
            if (!journal.MayHaveStartedInstallation || request?.LocalPolicyId != policy.CampaignId ||
                request.BoundAttemptId != journal.AttemptId || request.VerifiedRelease?.Version != version ||
                request.LifecycleGeneration != identity.Generation || request.TerminalReason is not null ||
                grant.CampaignId != policy.CampaignId || grant.TransactionId != transactionId || grant.Identity != identity ||
                grant.PolicySha256 != PolicyHash() || grant.Version != version || grant.AttemptId != journal.AttemptId ||
                grant.ArtifactSha256 != request.VerifiedRelease.ArtifactSha256 || grant.ExpiresUtc != request.ExpiresUtc ||
                grant.AdmittedUtc < policy.NotBeforeUtc || grant.AdmittedUtc >= grant.ExpiresUtc || grant.ExpiresUtc > policy.ExpiresAtUtc)
                throw new InvalidOperationException("Development MSI has no matching admitted updater attempt.");
            policy.RequireTarget(new(identity.AgentId, identity.TenantId, identity.Product), identity.KeyFingerprint, grant.AdmittedUtc);
            attempt = journal.AttemptId;
            artifact = request.VerifiedRelease.ArtifactSha256;
        }
        else
        {
            policy.RequireTarget(new(identity.AgentId, identity.TenantId, identity.Product), identity.KeyFingerprint, now);
            if (journal.HasUnfinishedAttempt) throw new InvalidOperationException("Bootstrap cannot replace an unfinished update attempt.");
        }
        var hashes = Metadata("AgentUpdateLabRuntimeHashesB64");
        _ = ParseHashes(hashes);
        var path = ReceiptPath(root, transactionId!);
        if (AgentUpdateDurableFile.Read<Admission>(path, root) is not null)
            throw new InvalidOperationException("Development MSI transaction admission cannot be reused.");
        var admissionTime = version == policy.Versions[0] ? now :
            AgentUpdateDurableFile.Read<LaunchGrant>(LaunchPath(root, transactionId!), root)!.AdmittedUtc;
        AgentUpdateDurableFile.Write(path, root, new Admission(policy.CampaignId, transactionId!, productCode.ToString("D"),
            version, PolicyHash(), hashes, identity, admissionTime, attempt, artifact));
    }

    internal static bool AllowRuntime(string runtime, Guid productCode, string version, string? transactionId)
    {
        var policy = Policy();
        if (policy is null) return false;
        RequireInvocation(policy, version, transactionId);
        var root = Root(policy);
        using var held = Lock(root);
        var admitted = AgentUpdateDurableFile.Read<Admission>(ReceiptPath(root, transactionId!), root)
            ?? throw new InvalidOperationException("Development MSI admission is missing.");
        var identity = ReadIdentity(requireActive: false);
        RequireContinuation(admitted, policy, productCode, version, transactionId!, identity, PolicyHash(),
            Metadata("AgentUpdateLabRuntimeHashesB64"));
        // Expiry affects new admission, not this same transaction's already-authorized file/health verification.
        foreach (var item in ParseHashes(admitted.RuntimeHashesBase64))
        {
            var path = Path.Combine(runtime, item.Key.Replace('/', Path.DirectorySeparatorChar));
            AgentUpdateSecurity.ValidateInstalledServiceSource(path, runtime);
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(file)), item.Value, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Development runtime differs from the admitted package payload.");
        }
        return true;
    }

    internal static void Complete(Guid productCode, string version, string? transactionId)
    {
        var policy = Policy();
        if (policy is null) return;
        RequireInvocation(policy, version, transactionId);
        var root = Root(policy);
        using var held = Lock(root);
        var path = ReceiptPath(root, transactionId!);
        var admission = AgentUpdateDurableFile.Read<Admission>(path, root) ?? throw new InvalidOperationException("MSI admission is missing.");
        RequireContinuation(admission, policy, productCode, version, transactionId!, ReadIdentity(false), PolicyHash(),
            Metadata("AgentUpdateLabRuntimeHashesB64"));
        AgentUpdateDurableFile.Write(path, root, admission with { Completed = true });
    }

    internal static void RequireContinuation(Admission admission, AgentUpdateLabPolicy policy, Guid productCode,
        string version, string transactionId, AgentStateDeliveryContext identity, string policyHash, string runtimeHashes)
    {
        if (admission.Completed || admission.CampaignId != policy.CampaignId || admission.TransactionId != transactionId ||
            admission.ProductCode != productCode.ToString("D") || admission.Version != version || admission.PolicySha256 != policyHash ||
            admission.RuntimeHashesBase64 != runtimeHashes || admission.Identity != identity ||
            admission.AdmittedUtc < policy.NotBeforeUtc || admission.AdmittedUtc >= policy.ExpiresAtUtc)
            throw new InvalidOperationException("Development MSI transaction authority changed or was already consumed.");
    }

    private static void RequireInvocation(AgentUpdateLabPolicy policy, string version, string? transactionId)
    {
        if (!AgentUpdateSecurity.IsLocalSystem() || !Guid.TryParseExact(transactionId, "D", out var transaction) || transaction == Guid.Empty ||
            typeof(AgentUpdateLabRuntimeAdmission).Assembly.GetName().Version?.ToString(3) != version)
            throw new InvalidOperationException("Development MSI transaction identity is invalid.");
        policy.RequireVersion(version);
    }

    private static AgentStateDeliveryContext ReadIdentity(bool requireActive)
    {
        var store = new DurableAgentLifecycleStateStore();
        var before = store.LoadAsync(default).GetAwaiter().GetResult();
        var loaded = new DpapiSecretStore(SecretStoreScope.Machine).LoadAsync(default).GetAwaiter().GetResult();
        var after = store.LoadAsync(default).GetAwaiter().GetResult();
        if (before.Generation != after.Generation || before.LastEnrollmentNonce != after.LastEnrollmentNonce ||
            loaded.Identity.Product != AgentProducts.Cerberus || AgentCredentialPublication.RecoveryRequired ||
            (requireActive && (!after.QuiescenceComplete || !AgentLifecycleStates.AllowsAutomaticNetwork(after.State))))
            throw new InvalidOperationException("Development MSI enrollment changed or is inactive.");
        return new(loaded.Identity.AgentId, loaded.Identity.TenantId, after.Generation, after.LastEnrollmentNonce,
            loaded.Identity.Product, AgentKeyFingerprint.FromPrivateKeyPem(loaded.PrivateKeyPem));
    }

    internal static Dictionary<string, string> ParseHashes(string encoded)
    {
        if (encoded.Length is 0 or > 16384) throw new InvalidOperationException("Development payload hashes are missing.");
        using var document = JsonDocument.Parse(Convert.FromBase64String(encoded));
        var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in document.RootElement.EnumerateObject())
        {
            var hash = item.Value.GetString();
            var segments = item.Name.Split('/');
            if (item.Name.Length > 256 || segments.Any(s => s.Length is 0 or > 128 || s is "." or ".." ||
                    s.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-'))) ||
                !segments[^1].StartsWith("Cerberus.", StringComparison.Ordinal) ||
                !(item.Name.EndsWith(".exe", StringComparison.Ordinal) || item.Name.EndsWith(".dll", StringComparison.Ordinal)) ||
                hash is not { Length: 64 } || !hash.All(Uri.IsHexDigit) || !hashes.TryAdd(item.Name, hash))
                throw new InvalidOperationException("Development payload hash metadata is invalid.");
        }
        if (!new[] { "Cerberus.Agent.exe", "Cerberus.Agent.Service.exe", "Cerberus.Agent.Updater.exe" }.All(hashes.ContainsKey))
            throw new InvalidOperationException("Development payload hashes do not cover all runtime executables.");
        return hashes;
    }

    private static string PolicyHash() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Metadata(AgentUpdateLabPolicy.MetadataName))));
    private static string Root(AgentUpdateLabPolicy policy)
    {
        var root = Path.Combine(AgentUpdateStager.DefaultStagingRoot, "lab-campaign-" + policy.CampaignId, "installer-transactions");
        AgentUpdateSecurity.EnsureProtectedRoot(root);
        return root;
    }
    private static FileStream Lock(string root)
    {
        var path = Path.Combine(root, "admission.lock");
        AgentUpdateSecurity.ValidateProtectedPath(path, root, allowMissing: true);
        return new(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }
    private static string ReceiptPath(string root, string transactionId) => Path.Combine(root, transactionId + ".json");
    private static string LaunchPath(string root, string transactionId) => Path.Combine(root, transactionId + ".launch.json");
}
