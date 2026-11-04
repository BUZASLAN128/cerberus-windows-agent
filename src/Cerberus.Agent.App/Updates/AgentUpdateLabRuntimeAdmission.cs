using System.Reflection;
using System.Diagnostics;
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
        string? AttemptId, string? ArtifactSha256, bool Completed = false, string? SourceVersion = null);
    internal sealed record LaunchGrant(string CampaignId, string TransactionId, string Version, string PolicySha256,
        AgentStateDeliveryContext Identity, DateTimeOffset AdmittedUtc, DateTimeOffset ExpiresUtc, string AttemptId, string ArtifactSha256,
        string SourceVersion);
    internal sealed record BootstrapLedger(string CampaignId, string PolicySha256, AgentStateDeliveryContext Identity,
        string TransactionId, string SourceVersion, string State);

    internal static void AdmitLaunch(AgentUpdateLabPolicy policy, AgentStateDeliveryContext identity,
        AgentUpdatePlan plan, AgentUpdateInstallRequest request, string transactionId)
    {
        var now = DateTimeOffset.UtcNow;
        policy.RequireTarget(new(identity.AgentId, identity.TenantId, identity.Product), identity.KeyFingerprint, now);
        policy.RequireVersion(plan.Version);
        var source = ReadInstalledSourceVersion();
        policy.RequireSuccessor(source, plan.Version);
        if (!AgentUpdateSecurity.IsLocalSystem() || !Guid.TryParseExact(transactionId, "D", out _) ||
            request.LocalPolicyId != policy.CampaignId || request.LocalSourceVersion != source || plan.LabSourceVersion != source ||
            request.ExpiresUtc <= now || request.ExpiresUtc > policy.ExpiresAtUtc ||
            request.BoundAttemptId != plan.AttemptId || request.VerifiedRelease is null ||
            !request.VerifiedRelease.Matches(AgentUpdateExpectedPlan.FromPlan(plan)))
            throw new InvalidOperationException("Development MSI launch grant is invalid.");
        var root = Root(policy);
        using var held = Lock(root);
        var path = LaunchPath(root, transactionId);
        if (File.Exists(path)) throw new InvalidOperationException("Development launch identity cannot be reused.");
        AgentUpdateDurableFile.Write(path, root, new LaunchGrant(policy.CampaignId, transactionId, plan.Version,
            PolicyHash(), identity, now, request.ExpiresUtc, plan.AttemptId!, plan.Sha256, source));
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
        // Read the installed, protected service image before StopServices/InstallFiles. This helper is the candidate, not the source.
        var sourceVersion = ReadInstalledSourceVersion();
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
                grant.SourceVersion != sourceVersion || request.LocalSourceVersion != sourceVersion ||
                grant.AdmittedUtc < policy.NotBeforeUtc || grant.AdmittedUtc >= grant.ExpiresUtc || grant.ExpiresUtc > policy.ExpiresAtUtc)
                throw new InvalidOperationException("Development MSI has no matching admitted updater attempt.");
            policy.RequireTarget(new(identity.AgentId, identity.TenantId, identity.Product), identity.KeyFingerprint, grant.AdmittedUtc);
            policy.RequireSuccessor(sourceVersion, version);
            attempt = journal.AttemptId;
            artifact = request.VerifiedRelease.ArtifactSha256;
        }
        else
        {
            var target = policy.RequireTarget(new(identity.AgentId, identity.TenantId, identity.Product), identity.KeyFingerprint, now);
            if (target.BootstrapSourceVersion != sourceVersion) throw new InvalidOperationException("Bootstrap installed baseline changed.");
            if (journal.HasUnfinishedAttempt) throw new InvalidOperationException("Bootstrap cannot replace an unfinished update attempt.");
            var previous = AgentUpdateDurableFile.Read<BootstrapLedger>(BootstrapPath(root), root);
            RequireBootstrapAvailable(previous, policy, identity, PolicyHash());
            // Pending is written before transaction admission. Ambiguous termination never grants a second bootstrap.
            AgentUpdateDurableFile.Write(BootstrapPath(root), root,
                new BootstrapLedger(policy.CampaignId, PolicyHash(), identity, transactionId!, sourceVersion, "pending"));
        }
        var hashes = Metadata("AgentUpdateLabRuntimeHashesB64");
        _ = ParseHashes(hashes);
        var path = ReceiptPath(root, transactionId!);
        if (AgentUpdateDurableFile.Read<Admission>(path, root) is not null)
            throw new InvalidOperationException("Development MSI transaction admission cannot be reused.");
        var admissionTime = version == policy.Versions[0] ? now :
            AgentUpdateDurableFile.Read<LaunchGrant>(LaunchPath(root, transactionId!), root)!.AdmittedUtc;
        AgentUpdateDurableFile.Write(path, root, new Admission(policy.CampaignId, transactionId!, productCode.ToString("D"),
            version, PolicyHash(), hashes, identity, admissionTime, attempt, artifact, SourceVersion: sourceVersion));
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
        RequireContinuation(admission with { Completed = false }, policy, productCode, version, transactionId!, ReadIdentity(false), PolicyHash(),
            Metadata("AgentUpdateLabRuntimeHashesB64"));
        if (!admission.Completed) AgentUpdateDurableFile.Write(path, root, admission with { Completed = true });
        if (version == policy.Versions[0])
        {
            var ledger = AgentUpdateDurableFile.Read<BootstrapLedger>(BootstrapPath(root), root)
                ?? throw new InvalidOperationException("Bootstrap ledger is missing.");
            var committed = CommitBootstrap(ledger, policy, admission.Identity, transactionId!, PolicyHash());
            if (ledger != committed) AgentUpdateDurableFile.Write(BootstrapPath(root), root, committed);
        }
    }

    internal static void Rollback(Guid productCode, string version, string? transactionId)
    {
        var policy = Policy();
        if (policy is null) return;
        RequireInvocation(policy, version, transactionId);
        if (version != policy.Versions[0]) return;
        var identity = ReadIdentity(false);
        var root = Root(policy);
        using var held = Lock(root);
        var ledger = AgentUpdateDurableFile.Read<BootstrapLedger>(BootstrapPath(root), root);
        if (ledger is null) return;
        // Rollback retires this pending transaction; a committed campaign/device boundary is never erased.
        var retired = RollbackBootstrap(ledger, policy, identity, transactionId!, PolicyHash());
        if (ledger != retired) AgentUpdateDurableFile.Write(BootstrapPath(root), root, retired);
    }

    internal static BootstrapLedger CommitBootstrap(BootstrapLedger ledger, AgentUpdateLabPolicy policy,
        AgentStateDeliveryContext identity, string transactionId, string policyHash)
    {
        RequireBootstrapTransaction(ledger, policy, identity, transactionId, policyHash);
        if (ledger.State is not ("pending" or "committed")) throw new InvalidOperationException("Bootstrap already rolled back.");
        return ledger.State == "committed" ? ledger : ledger with { State = "committed" };
    }

    internal static BootstrapLedger RollbackBootstrap(BootstrapLedger ledger, AgentUpdateLabPolicy policy,
        AgentStateDeliveryContext identity, string transactionId, string policyHash)
    {
        RequireBootstrapTransaction(ledger, policy, identity, transactionId, policyHash);
        if (ledger.State is not ("pending" or "committed" or "rolled_back")) throw new InvalidOperationException("Bootstrap ledger state is invalid.");
        return ledger.State == "pending" ? ledger with { State = "rolled_back" } : ledger;
    }

    internal static void RequireBootstrapAvailable(BootstrapLedger? ledger, AgentUpdateLabPolicy policy,
        AgentStateDeliveryContext identity, string policyHash)
    {
        if (ledger is null) return;
        if (ledger.CampaignId != policy.CampaignId || ledger.PolicySha256 != policyHash ||
            ledger.Identity.AgentId != identity.AgentId || ledger.Identity.TenantId != identity.TenantId ||
            ledger.Identity.KeyFingerprint != identity.KeyFingerprint || ledger.Identity.Product != identity.Product || ledger.State != "rolled_back")
            throw new InvalidOperationException("Bootstrap is already committed, pending, or belongs to another target.");
    }

    private static void RequireBootstrapTransaction(BootstrapLedger ledger, AgentUpdateLabPolicy policy,
        AgentStateDeliveryContext identity, string transactionId, string policyHash)
    {
        if (ledger.CampaignId != policy.CampaignId || ledger.PolicySha256 != policyHash || ledger.Identity != identity ||
            ledger.TransactionId != transactionId || !policy.Targets.Any(t => t.AgentId == identity.AgentId &&
                t.TenantId == identity.TenantId && t.KeyFingerprint == identity.KeyFingerprint && t.BootstrapSourceVersion == ledger.SourceVersion))
            throw new InvalidOperationException("Bootstrap transaction authority changed.");
    }

    internal static void RequireContinuation(Admission admission, AgentUpdateLabPolicy policy, Guid productCode,
        string version, string transactionId, AgentStateDeliveryContext identity, string policyHash, string runtimeHashes)
    {
        if (admission.Completed || admission.CampaignId != policy.CampaignId || admission.TransactionId != transactionId ||
            admission.ProductCode != productCode.ToString("D") || admission.Version != version || admission.PolicySha256 != policyHash ||
            admission.RuntimeHashesBase64 != runtimeHashes || admission.Identity != identity ||
            admission.AdmittedUtc < policy.NotBeforeUtc || admission.AdmittedUtc >= policy.ExpiresAtUtc)
            throw new InvalidOperationException("Development MSI transaction authority changed or was already consumed.");
        if (version == policy.Versions[0])
        {
            var target = policy.Targets.Single(t => t.AgentId == identity.AgentId && t.TenantId == identity.TenantId);
            if (admission.SourceVersion != target.BootstrapSourceVersion) throw new InvalidOperationException("Bootstrap source changed.");
        }
        else policy.RequireSuccessor(admission.SourceVersion ?? "", version);
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
    private static string BootstrapPath(string root) => Path.Combine(root, "bootstrap.json");
    private static string LaunchPath(string root, string transactionId) => Path.Combine(root, transactionId + ".launch.json");

    private static string ReadInstalledSourceVersion()
    {
        var runtime = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cerberus", "Server Agent", "app");
        var service = Path.Combine(runtime, "Cerberus.Agent.Service.exe");
        AgentUpdateSecurity.ValidateInstalledServiceSource(service, runtime);
        var version = AgentUpdateCampaignTransition.Release(FileVersionInfo.GetVersionInfo(service).ProductVersion ?? "");
        if (!Version.TryParse(version, out var parsed) || parsed.Build < 0 || parsed.Revision != -1 || parsed.ToString(3) != version)
            throw new InvalidOperationException("Installed service release version is missing.");
        return version;
    }

}
