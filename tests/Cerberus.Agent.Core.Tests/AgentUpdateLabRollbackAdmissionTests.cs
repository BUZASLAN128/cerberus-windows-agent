using Cerberus.Agent.App.Updates;
using System.Text;
using System.Text.Json;
using Admission = Cerberus.Agent.App.Updates.AgentUpdateLabRuntimeAdmission;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateLabRollbackAdmissionTests
{
    private readonly AgentUpdateLabPolicy _policy = AgentUpdateLabPolicyTests.Valid();
    private const string Attempt = "forward-attempt", Rollback = "rollback-attempt", PolicyHash = "fixture-policy-hash";
    private static readonly string MsiHash = new('a', 64);
    private static readonly string UpdaterHash = new('b', 64);
    private static readonly string Hashes = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(
        new Dictionary<string, string> { ["Cerberus.Agent.exe"] = UpdaterHash, ["Cerberus.Agent.Service.exe"] = UpdaterHash,
            ["Cerberus.Agent.Updater.exe"] = UpdaterHash })));
    private readonly Guid _product = Guid.NewGuid();
    private readonly string _transaction = Guid.NewGuid().ToString("D");

    [Fact]
    public void RollbackAdmissionBindsGrantAndCompletedRawPredecessor()
    {
        var current = _policy.Versions[5];
        var target = _policy.Versions[4];
        var now = _policy.NotBeforeUtc.AddHours(1);
        var identity = new AgentStateDeliveryContext("pc", "tenant", 7, "nonce", AgentProducts.Cerberus,
            _policy.Targets[0].KeyFingerprint);
        var activeRelease = new AgentUpdateExpectedPlan(current, "dev:100", MsiHash);
        var request = new AgentUpdateInstallRequest(now, identity.Generation, now.AddHours(1), ExpectedPlan: activeRelease,
            LocalPolicyId: _policy.CampaignId, LocalSourceVersion: target, BoundAttemptId: Attempt, VerifiedRelease: activeRelease);
        var journal = new AgentUpdateJournal { Phase = AgentUpdateWatchJournal.RollingBack, AttemptId = Attempt,
            RollbackAttemptId = Rollback, LifecycleGeneration = identity.Generation, InstallRequest = request };
        var forward = new Admission.Admission(_policy.CampaignId, Guid.NewGuid().ToString("D"), _product.ToString("D"),
            target, PolicyHash, Hashes, identity, now.AddMinutes(-10), "prior-attempt", MsiHash, Completed: true,
            SourceVersion: _policy.Versions[3]);
        var grant = new Admission.RollbackAdmissionGrant(_policy.CampaignId, _transaction, PolicyHash, identity,
            Attempt, Rollback, current, target, MsiHash, now, now.AddMinutes(30));
        Admission.Admission Begin(Admission.RollbackAdmissionGrant? g, AgentUpdateJournal j, Admission.Admission a,
            string? source = null, DateTimeOffset? time = null) => Admission.RequireRollbackBegin(g, a, j, _policy,
                identity, _product, target, source ?? current, _transaction, PolicyHash, Hashes, time ?? now);

        var admitted = Begin(grant, journal, forward);
        Assert.Equal("rollback", admitted.Kind);
        Assert.Equal(current, admitted.SourceVersion);
        Admission.RequireContinuation(admitted, _policy, _product, target, _transaction, identity, PolicyHash, Hashes);
        Assert.Throws<InvalidOperationException>(() => Begin(null, journal, forward));
        Assert.Throws<InvalidOperationException>(() => Begin(grant with { RollbackAttemptId = "other" }, journal, forward));
        Assert.Throws<InvalidOperationException>(() => Begin(grant, journal with { Phase = AgentUpdateWatchJournal.CommittedWatch }, forward));
        Assert.Throws<InvalidOperationException>(() => Begin(grant with { SourceVersion = _policy.Versions[3] }, journal, forward, _policy.Versions[3]));
        Assert.Throws<InvalidOperationException>(() => Begin(grant, journal, forward with { ArtifactSha256 = UpdaterHash }));
        Assert.Throws<InvalidOperationException>(() => Begin(grant, journal, forward with { Completed = false }));
        Assert.Throws<InvalidOperationException>(() => Begin(grant, journal, forward, time: grant.ExpiresUtc));
    }

    [Fact]
    public void CompletedVersionReceiptIsBoundAndCannotBeReplacedOrReused()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-lab-admission-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var now = _policy.NotBeforeUtc.AddHours(1);
            var version = _policy.Versions[4];
            var identity = new AgentStateDeliveryContext("pc", "tenant", 7, "nonce", AgentProducts.Cerberus,
                _policy.Targets[0].KeyFingerprint);
            var forward = new Admission.Admission(_policy.CampaignId, _transaction, _product.ToString("D"), version,
                PolicyHash, Hashes, identity, now, Attempt, MsiHash, Completed: true);
            var path = Path.Combine(root, "updater-" + version + ".json");
            Admission.RequireUnusedAdmission(root, _transaction);
            AgentUpdateDurableFile.Write(Path.Combine(root, _transaction + ".json"), root, forward);
            Assert.Throws<InvalidOperationException>(() => Admission.RequireUnusedAdmission(root, _transaction));
            Admission.WriteVersionReceipt(root, forward, now);
            var firstBytes = File.ReadAllBytes(path);
            Admission.WriteVersionReceipt(root, forward, now.AddSeconds(1));
            Admission.WriteVersionReceipt(root, forward with { ArtifactSha256 = UpdaterHash }, now.AddSeconds(2));
            Assert.Equal(firstBytes, File.ReadAllBytes(path));
            var receipt = AgentUpdateDurableFile.Read<Admission.VersionReceipt>(path, root)!;
            Assert.True(Admission.MatchesVersionReceipt(receipt, forward, _policy, identity, version, PolicyHash));
            Assert.False(Admission.MatchesVersionReceipt(receipt, forward with { ArtifactSha256 = UpdaterHash }, _policy, identity, version, PolicyHash));
            Assert.False(Admission.MatchesVersionReceipt(receipt, forward, _policy with { CampaignId = Guid.NewGuid().ToString("D") },
                identity, version, PolicyHash));
            Assert.False(Admission.IsAdmittedLabArtifact("updater", version, UpdaterHash));
            Assert.False(AgentUpdateLabRuntime.IsAdmittedLabArtifact("msi", version, MsiHash));
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
