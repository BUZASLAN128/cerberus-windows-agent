using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateLabRemediationTests
{
    private const string Feed = "https://feed.example.invalid/updates/devtest/";
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private static readonly string Key = "sha256:" + new string('a', 64);
    private static AgentUpdateLabPolicy Policy() => new("agent.update.lab.v1", "ed09dbf0-973b-419d-9235-299759ac14c3",
        Now.AddMinutes(-5), Now.AddHours(1),
        [new("pc", "tenant", Key, Feed + "pc/latest.json", Feed, "0.2.1010"),
         new("vm", "tenant", "sha256:" + new string('b', 64), Feed + "vm106/latest.json", Feed, "0.2.1011")],
        Enumerable.Range(900, 11).Select(v => $"0.2.{v}").ToArray(), "https://collector.example.invalid", "https://sso.invalid");
    private static AgentStateDeliveryContext Identity() => new("pc", "tenant", 7, "nonce", AgentProducts.Cerberus, Key);

    [Fact]
    public void UpdaterFaultUsesDurableAuthorityWithoutAServiceProcessCallback()
    {
        var policy = Policy();
        var scope = new AgentUpdateLabRuntime.Scope(policy, policy.Targets[0], Identity());
        var plan = new AgentUpdatePlan("msi", "0.2.908", "dev", "payload", new('a', 64), Now.ToString("O"), "lab",
            AttemptId: new('a', 32), Sequence: 8, LabSourceVersion: "0.2.907");
        var release = AgentUpdateExpectedPlan.FromPlan(plan);
        var request = new AgentUpdateInstallRequest(Now, 7, Now.AddMinutes(30), ExpectedPlan: release,
            LocalPolicyId: policy.CampaignId, LocalSourceVersion: "0.2.907", BoundAttemptId: plan.AttemptId, VerifiedRelease: release);
        var active = new AgentUpdateJournal { Phase = "launch_requested", AttemptId = plan.AttemptId, LifecycleGeneration = 7,
            RunnerProcessId = 123, RunnerStartedUtc = Now, InstallRequest = request };
        var lifecycle = new AgentLifecycleSnapshot { Generation = 7, LastEnrollmentNonce = "nonce" };
        Assert.True(AgentUpdateLocalService.Quarantined(null, isServer: true)); // Deliberately remains fail closed.
        bool Eligible(AgentUpdateJournal a, AgentLifecycleSnapshot l, bool quarantine = false, bool pending = false)
            => AgentUpdateLabFaults.ShouldInterruptUpdater(scope, a, plan, l, 123, Now, quarantine, pending);
        AgentUpdateLabRuntime.RequireLaunchScope(scope, active, 7, Now, "0.2.907");
        Assert.True(Eligible(active, lifecycle));
        Assert.False(Eligible(active, lifecycle, quarantine: true));
        Assert.False(Eligible(active, lifecycle, pending: true));
        Assert.False(Eligible(active, lifecycle with { Generation = 8 }));
        Assert.False(Eligible(active, lifecycle with { LastEnrollmentNonce = "changed" }));
        Assert.False(Eligible(active with { RunnerProcessId = 456 }, lifecycle));
        Assert.False(Eligible(active with { Phase = "install_may_have_started" }, lifecycle));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntime.RequireLaunchScope(scope, active, 7, policy.ExpiresAtUtc, "0.2.907"));
    }

    [Fact]
    public async Task SignedFutureManifestCannotAdvanceFloorAndCurrentPollingDoesNotWriteIt()
    {
        using var rsa = RSA.Create(2048);
        var policy = Policy();
        var root = Path.Combine(Path.GetTempPath(), "cerberus-lab-next-" + Guid.NewGuid().ToString("N"));
        var trust = new AgentUpdateTrust([rsa.ExportSubjectPublicKeyInfoPem()], "dev", [Feed], "0.2.900",
            ConfiguredManifestUrl: Feed + "latest.json", AllowedSignerKeyIdentity: "unsigned-dev", AllowUnsignedDevBuild: true,
            RequireManifestV2: true, TestCampaignVersions: policy.Versions);
        var signal = new AgentUpdateSignal(false, true, trust.ConfiguredManifestUrl, "lab", "dev");
        async Task<AgentUpdateExpectedPlan> Read(string version)
        {
            var manifest = new AgentUpdateManifest("msi", version, "dev", Feed + version + ".msi", new('a', 64),
                "lab", Now.AddMinutes(-1).ToString("O"), "agent.heartbeat.v1", false, "",
                SchemaVersion: AgentUpdateManifest.V2SchemaVersion, Sequence: Now.ToUnixTimeMilliseconds(),
                ExpiresAtUtc: Now.AddHours(1).ToString("O"), ArtifactLength: 42, SignerKeyIdentity: "unsigned-dev");
            manifest = manifest with { Signature = Convert.ToBase64String(rsa.SignData(
                Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(manifest)), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) };
            using var http = new HttpClient(new ManifestHandler(JsonSerializer.Serialize(manifest)));
            return await new AgentUpdateStager(http, trust, root).GetTrustedReleaseAsync(signal, default);
        }
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Read("0.2.910"));
        Assert.Contains("immediate successor", error.Message);
        Assert.False(File.Exists(Path.Combine(root, "highest-sequence.json")));
        Assert.Equal("0.2.900", (await Read("0.2.900")).Version);
        Assert.False(File.Exists(Path.Combine(root, "highest-sequence.json")));
    }

    [Fact]
    public void RequestAndLaunchStayBoundToTheActualImmediatePredecessor()
    {
        var policy = Policy();
        var release = new AgentUpdateExpectedPlan("0.2.901", "dev:1", new('a', 64));
        var journal = AgentUpdateLocalService.AdmitLabInstallRequest(new(), policy, release, 7, Now, "0.2.900+installed");
        Assert.Equal("0.2.900", journal.InstallRequest!.LocalSourceVersion);
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLocalService.AdmitLabInstallRequest(new(), policy,
            release with { Version = "0.2.910" }, 7, Now, "0.2.900"));
        var bound = journal with { AttemptId = new('a', 32), LifecycleGeneration = 7,
            InstallRequest = journal.InstallRequest with { BoundAttemptId = new('a', 32), VerifiedRelease = release } };
        var scope = new AgentUpdateLabRuntime.Scope(policy, policy.Targets[0], Identity());
        AgentUpdateLabRuntime.RequireLaunchScope(scope, bound, 7, Now, "0.2.900");
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntime.RequireLaunchScope(scope, bound, 7, Now, "0.2.901"));
        Assert.Throws<InvalidOperationException>(() => policy.RequireSuccessor("0.2.910", "0.2.911"));
        Assert.Throws<InvalidOperationException>(() => policy.RequireSuccessor("0.2.908", "0.2.907"));
    }

    [Fact]
    public void BootstrapCommitIsOncePerCampaignDeviceAndRollbackOnlyRetiresPendingAdmission()
    {
        var policy = Policy(); var identity = Identity(); var transaction = Guid.NewGuid().ToString("D");
        var pending = new AgentUpdateLabRuntimeAdmission.BootstrapLedger(policy.CampaignId, "policy-hash", identity, transaction, "0.2.1010", "pending");
        Assert.False(AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(null, policy, identity, "policy-hash"));
        Assert.False(AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(pending, policy, identity, "policy-hash"));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.RequireBootstrapAvailable(pending, policy, identity, "policy-hash"));
        var rolledBack = AgentUpdateLabRuntimeAdmission.RollbackBootstrap(pending, policy, identity, transaction, "policy-hash");
        AgentUpdateLabRuntimeAdmission.RequireBootstrapAvailable(rolledBack, policy, identity, "policy-hash");
        Assert.False(AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(rolledBack, policy, identity, "policy-hash"));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.CommitBootstrap(rolledBack, policy, identity, transaction, "policy-hash"));
        var committed = AgentUpdateLabRuntimeAdmission.CommitBootstrap(pending, policy, identity, transaction, "policy-hash");
        Assert.True(AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(committed, policy, identity, "policy-hash"));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(committed, policy,
            identity with { KeyFingerprint = "changed" }, "policy-hash"));
        Assert.Same(committed, AgentUpdateLabRuntimeAdmission.CommitBootstrap(committed, policy, identity, transaction, "policy-hash"));
        Assert.Same(committed, AgentUpdateLabRuntimeAdmission.RollbackBootstrap(committed, policy, identity, transaction, "policy-hash"));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.RequireBootstrapAvailable(committed, policy, identity with { Generation = 8 }, "policy-hash"));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.CommitBootstrap(pending, policy, identity, Guid.NewGuid().ToString("D"), "policy-hash"));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.CommitBootstrap(pending, policy, identity with { KeyFingerprint = "changed" }, transaction, "policy-hash"));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.CommitBootstrap(pending, policy, identity, transaction, "changed-policy"));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.CommitBootstrap(pending with { SourceVersion = "0.2.1011" }, policy, identity, transaction, "policy-hash"));
    }

    [Fact]
    public async Task SameSchedulerWaitsWhileBootstrapPendingThenAdmitsFirstSuccessorWithoutRestart()
    {
        var policy = Policy(); var identity = Identity(); var transaction = Guid.NewGuid().ToString("D");
        var ledger = new AgentUpdateLabRuntimeAdmission.BootstrapLedger(policy.CampaignId, "policy-hash", identity, transaction, "0.2.1010", "pending");
        var scope = new AgentUpdateLabRuntime.Scope(policy, policy.Targets[0], identity);
        var journal = new AgentUpdateJournal();
        var feedAdmissions = 0;
        Task Admit(CancellationToken _)
        {
            feedAdmissions++;
            journal = AgentUpdateLocalService.AdmitLabInstallRequest(journal, policy,
                new("0.2.901", "dev:1", new('a', 64)), 7, Now, "0.2.900");
            return Task.CompletedTask;
        }
        Task<bool> Tick() => AgentUpdateLocalService.RunLabTickAfterBootstrapAsync(scope,
            s => AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(ledger, s.Policy, s.Context, "policy-hash"), Admit, default);
        Assert.False(await Tick());
        Assert.False(await Tick());
        Assert.Equal(0, feedAdmissions);
        Assert.Null(journal.InstallRequest);
        ledger = AgentUpdateLabRuntimeAdmission.CommitBootstrap(ledger, policy, identity, transaction, "policy-hash");
        Assert.True(await Tick());
        Assert.Equal(1, feedAdmissions);
        Assert.Equal("0.2.901", journal.InstallRequest!.ExpectedPlan!.Version);
        Assert.Equal("0.2.900", journal.InstallRequest.LocalSourceVersion);
    }

    [Fact]
    public void ConsumptionIsScheduledAtMsiCommitAndRollbackPrecedesBootstrap()
    {
        var root = ServerPackageStaticTests.FindRepoRoot();
        var package = XDocument.Load(Path.Combine(root, "src", "Cerberus.Agent.Installer", "Package.wxs"));
        XNamespace wix = "http://wixtoolset.org/schemas/v4/wxs";
        var commit = package.Descendants(wix + "CustomAction").Single(x => (string?)x.Attribute("Id") == "CommitLabCampaignAdmission");
        Assert.Equal("commit", (string?)commit.Attribute("Execute"));
        Assert.Equal("no", (string?)commit.Attribute("Impersonate"));
        var rollback = package.Descendants(wix + "Custom").Single(x => (string?)x.Attribute("Action") == "RollbackLabCampaignAdmission");
        Assert.Equal("BootstrapCerberusMachineNamespace", (string?)rollback.Attribute("Before"));
    }

    private sealed class ManifestHandler(string json) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { RequestMessage = request, Content = new StringContent(json) });
    }
}
