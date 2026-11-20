#if !CERBERUS_EXCLUDE_UPDATE_CAMPAIGN // Campaign code is not compiled with -p:ExcludeUpdateCampaignCode=true.
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentUpdateLabRemediationTests
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
        var plan = new AgentUpdatePlan("msi", "0.2.909", "dev", "payload", new('a', 64), Now.ToString("O"), "lab",
            AttemptId: new('a', 32), Sequence: 9, LabSourceVersion: "0.2.908");
        var release = AgentUpdateExpectedPlan.FromPlan(plan);
        var request = new AgentUpdateInstallRequest(Now, 7, Now.AddMinutes(30), ExpectedPlan: release,
            LocalPolicyId: policy.CampaignId, LocalSourceVersion: "0.2.908", BoundAttemptId: plan.AttemptId, VerifiedRelease: release);
        var active = new AgentUpdateJournal { Phase = "launch_requested", AttemptId = plan.AttemptId, LifecycleGeneration = 7,
            RunnerProcessId = 123, RunnerStartedUtc = Now, InstallRequest = request };
        var lifecycle = new AgentLifecycleSnapshot { Generation = 7, LastEnrollmentNonce = "nonce" };
        Assert.True(AgentUpdateLocalService.Quarantined(null, isServer: true)); // Deliberately remains fail closed.
        bool Eligible(AgentUpdateJournal a, AgentLifecycleSnapshot l, bool quarantine = false, bool pending = false)
            => AgentUpdateLabFaults.ShouldInterruptUpdater(scope, a, plan, l, 123, Now, quarantine, pending);
        AgentUpdateLabRuntime.RequireLaunchScope(scope, active, 7, Now, "0.2.908");
        Assert.True(Eligible(active, lifecycle));
        Assert.False(Eligible(active, lifecycle, quarantine: true));
        Assert.False(Eligible(active, lifecycle, pending: true));
        Assert.False(Eligible(active, lifecycle with { Generation = 8 }));
        Assert.False(Eligible(active, lifecycle with { LastEnrollmentNonce = "changed" }));
        Assert.False(Eligible(active with { RunnerProcessId = 456 }, lifecycle));
        Assert.False(Eligible(active with { Phase = "install_may_have_started" }, lifecycle));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntime.RequireLaunchScope(scope, active, 7, policy.ExpiresAtUtc, "0.2.908"));

        foreach (var index in new[] { 1, 2, 3, 4, 5, 6, 7, 8, 10 })
        {
            var candidate = plan with { Version = policy.Versions[index], LabSourceVersion = policy.Versions[index - 1] };
            var verified = AgentUpdateExpectedPlan.FromPlan(candidate);
            var bound = active with { InstallRequest = request with { ExpectedPlan = verified,
                VerifiedRelease = verified, LocalSourceVersion = candidate.LabSourceVersion } };
            Assert.Equal(index is 6,
                AgentUpdateLabFaults.ShouldInterruptUpdater(scope, bound, candidate, lifecycle, 123, Now, false, false));
        }
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
    public async Task CommittedNewBootstrapPreservesForeignFailedReceiptBeforeAdmittingItsSuccessor()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-lab-handover-" + Guid.NewGuid().ToString("N"));
        var policy = Policy(); var identity = Identity();
        var ledger = new AgentUpdateLabRuntimeAdmission.BootstrapLedger(policy.CampaignId, "policy-hash", identity,
            Guid.NewGuid().ToString("D"), "0.2.960", "committed");
        var store = new AgentUpdateJournalStore(root);
        store.Change(_ => ClosedForeignFailure());
        var original = store.Read();
        string? retainedPath = null;
        var scope = new AgentUpdateLabRuntime.Scope(policy, policy.Targets[0], identity);
        var release = new AgentUpdateExpectedPlan("0.2.901", "dev:new", new('a', 64));
        Task Admit(CancellationToken _)
        {
            Assert.True(AgentUpdateLocalService.CanContinueLabCampaign(store.Read(), policy, "0.2.900", true));
            store.Change(before => AgentUpdateLocalService.AdmitLabInstallRequest(before, policy, release, 7, Now,
                "0.2.900+installed", true, snapshot => retainedPath = AgentUpdateLocalService.PreserveClosedLabFailure(root, snapshot)));
            return Task.CompletedTask;
        }
        Assert.True(await AgentUpdateLocalService.RunLabTickAfterBootstrapAsync(scope,
            s => AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(ledger, s.Policy, s.Context, "policy-hash"), Admit, default));
        var admitted = new AgentUpdateJournalStore(root).Read();
        Assert.Equal(policy.CampaignId, admitted.InstallRequest!.LocalPolicyId);
        Assert.Equal("0.2.900", admitted.InstallRequest.LocalSourceVersion);
        Assert.Equal("0.2.901", admitted.InstallRequest.ExpectedPlan!.Version);
        Assert.True(admitted.InstallRequest.IsPending);
        Assert.Equal(original with { Revision = admitted.Revision, InstallRequest = admitted.InstallRequest }, admitted);
        Assert.Equal(original, AgentUpdateDurableFile.Read<AgentUpdateJournal>(retainedPath!, root));
        var retainedBytes = File.ReadAllBytes(retainedPath!);
        var repeated = AgentUpdateLocalService.AdmitLabInstallRequest(admitted, policy, release, 7, Now.AddMinutes(5),
            "0.2.900", true, _ => throw new InvalidOperationException("A pending request cannot be renewed."));
        Assert.Same(admitted, repeated);
        Assert.Equal(retainedBytes, File.ReadAllBytes(retainedPath!));
    }

    [Fact]
    public void FailedHandoverRequiresDifferentPolicyCommitAndDurablePreservation()
    {
        var policy = Policy(); var failed = ClosedForeignFailure();
        var release = new AgentUpdateExpectedPlan("0.2.901", "dev:new", new('a', 64));
        Assert.Same(failed, AgentUpdateLocalService.AdmitLabInstallRequest(failed, policy, release, 7, Now, "0.2.900", true));
        var writes = 0;
        AgentUpdateJournal Admit(AgentUpdateJournal before, bool committed = true, string installed = "0.2.900") =>
            AgentUpdateLocalService.AdmitLabInstallRequest(before, policy, release, 7, Now, installed, committed, _ => writes++);
        Assert.Same(failed, Admit(failed, false));
        // A successor manifest for another installed release cannot transfer the predecessor.
        Assert.Throws<InvalidOperationException>(() => Admit(failed, true, "0.2.901"));
        var samePolicy = failed with { InstallRequest = failed.InstallRequest! with { LocalPolicyId = policy.CampaignId } };
        Assert.False(AgentUpdateLocalService.CanContinueLabCampaign(samePolicy, policy, "0.2.900", true));
        Assert.Same(samePolicy, Admit(samePolicy));
        Assert.Same(samePolicy, Admit(samePolicy));
        Assert.Equal(0, writes);
    }

    [Theory]
    [InlineData("bound")]
    [InlineData("terminal-attempt")]
    [InlineData("terminal-phase")]
    [InlineData("result-attempt")]
    [InlineData("result-state")]
    [InlineData("quarantine")]
    [InlineData("generation")]
    [InlineData("verified-release")]
    [InlineData("recovery-required")]
    [InlineData("recovery-timeout")]
    [InlineData("reboot")]
    [InlineData("exit-zero")]
    [InlineData("unknown-with-exit")]
    [InlineData("pre-launch-recovery-required")]
    public void InconsistentOrUnfinishedFailureCannotBeHandedOver(string changed)
    {
        var policy = Policy(); var failed = ClosedForeignFailure(); var request = failed.InstallRequest!;
        failed = changed switch
        {
            "recovery-timeout" => failed with { InstallerResult = failed.InstallerResult! with { ErrorCode = "recovery_timeout", MsiExitCode = null } },
            "reboot" => failed with { InstallerResult = failed.InstallerResult! with { RequiresReboot = true } },
            "exit-zero" => failed with { InstallerResult = failed.InstallerResult! with { MsiExitCode = 0 } },
            "unknown-with-exit" => failed with { InstallerResult = failed.InstallerResult! with { ErrorCode = "unknown" } },
            "pre-launch-recovery-required" => PreLaunchUpdaterFailure() with { Phase = AgentUpdateStates.RecoveryRequired },
            "bound" => failed with { InstallRequest = request with { BoundAttemptId = new('b', 32) } },
            "terminal-attempt" => failed with { InstallRequest = request with { TerminalJournalAttemptId = new('b', 32) } },
            "terminal-phase" => failed with { InstallRequest = request with { TerminalJournalPhase = AgentUpdateStates.Installed } },
            "result-attempt" => failed with { InstallerResult = failed.InstallerResult! with { AttemptId = new('b', 32) } },
            "result-state" => failed with { InstallerResult = failed.InstallerResult! with { State = AgentUpdateStates.Installed } },
            "quarantine" => failed with { InstallerResult = failed.InstallerResult! with { Quarantined = true } },
            "generation" => failed with { LifecycleGeneration = 8 },
            "verified-release" => failed with { InstallRequest = request with { VerifiedRelease = request.VerifiedRelease! with { Version = "0.2.942" } } },
            "recovery-required" => failed with { Phase = AgentUpdateStates.RecoveryRequired },
            _ => throw new InvalidOperationException()
        };
        var release = new AgentUpdateExpectedPlan("0.2.901", "dev:new", new('a', 64));
        Assert.False(AgentUpdateLocalService.CanContinueLabCampaign(failed, policy, "0.2.900", true));
        Assert.Same(failed, AgentUpdateLocalService.AdmitLabInstallRequest(failed, policy, release, 7, Now, "0.2.900", true,
            _ => throw new InvalidOperationException("Invalid predecessors cannot write receipts.")));
    }

    [Fact]
    public void InterruptedHandoverRetainsTheFailureAndCanRetryWithoutReplacingItsReceipt()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-lab-handover-crash-" + Guid.NewGuid().ToString("N"));
        var store = new AgentUpdateJournalStore(root); store.Change(_ => ClosedForeignFailure());
        var original = store.Read(); var policy = Policy();
        var release = new AgentUpdateExpectedPlan("0.2.901", "dev:new", new('a', 64));
        string? retainedPath = null;
        Assert.Throws<IOException>(() => store.Change(before => AgentUpdateLocalService.AdmitLabInstallRequest(before,
            policy, release, 7, Now, "0.2.900", true, snapshot =>
            {
                retainedPath = AgentUpdateLocalService.PreserveClosedLabFailure(root, snapshot);
                throw new IOException("Simulated interruption before journal replacement.");
            })));
        Assert.Equal(original, new AgentUpdateJournalStore(root).Read());
        var bytes = File.ReadAllBytes(retainedPath!);
        store.Change(before => AgentUpdateLocalService.AdmitLabInstallRequest(before, policy, release, 7, Now,
            "0.2.900", true, snapshot => AgentUpdateLocalService.PreserveClosedLabFailure(root, snapshot)));
        Assert.Equal(bytes, File.ReadAllBytes(retainedPath!));
        Assert.Equal(original, AgentUpdateDurableFile.Read<AgentUpdateJournal>(retainedPath!, root));
        Assert.Equal(policy.CampaignId, store.Read().InstallRequest!.LocalPolicyId);
    }

    [Fact]
    public void ConflictingPreservationFailsClosedWithoutReplacingTheActiveJournal()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-lab-handover-conflict-" + Guid.NewGuid().ToString("N"));
        var store = new AgentUpdateJournalStore(root); store.Change(_ => ClosedForeignFailure());
        var original = store.Read(); var path = AgentUpdateLocalService.PreserveClosedLabFailure(root, original);
        var conflicting = original with { FailedInstallSequence = original.FailedInstallSequence + 1 };
        AgentUpdateDurableFile.Write(path, root, conflicting);
        var policy = Policy(); var release = new AgentUpdateExpectedPlan("0.2.901", "dev:new", new('a', 64));
        Assert.Throws<InvalidOperationException>(() => store.Change(before => AgentUpdateLocalService.AdmitLabInstallRequest(before,
            policy, release, 7, Now, "0.2.900", true, snapshot => AgentUpdateLocalService.PreserveClosedLabFailure(root, snapshot))));
        Assert.Equal(original, store.Read());
        Assert.Equal(conflicting, AgentUpdateDurableFile.Read<AgentUpdateJournal>(path, root));
        File.WriteAllText(path, "not-json");
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLocalService.PreserveClosedLabFailure(root, original));
        Assert.Equal(original, store.Read());
    }

    [Fact]
    public void UpdaterFailureBeforeItsInstallerLaunchCanBeHandedOver()
    {
        var policy = Policy(); var failed = PreLaunchUpdaterFailure(); var writes = 0;
        var release = new AgentUpdateExpectedPlan("0.2.901", "dev:new", new('a', 64));
        Assert.True(AgentUpdateLocalService.CanContinueLabCampaign(failed, policy, "0.2.900", true));
        var admitted = AgentUpdateLocalService.AdmitLabInstallRequest(failed, policy, release, 7, Now, "0.2.900", true, _ => writes++);
        Assert.Equal(1, writes);
        Assert.Equal(policy.CampaignId, admitted.InstallRequest!.LocalPolicyId);
    }

    [Fact]
    public void StagingThatGaveUpBeforeBindingIsHandedOverWithItsReceipt()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-lab-handover-staging-" + Guid.NewGuid().ToString("N"));
        var store = new AgentUpdateJournalStore(root); store.Change(_ => GaveUpStaging());
        var original = store.Read(); var policy = Policy(); string? retained = null;
        Assert.True(AgentUpdateLocalService.CanContinueLabCampaign(original, policy, "0.2.900", true));
        store.Change(before => AgentUpdateLocalService.AdmitLabInstallRequest(before, policy, new("0.2.901", "dev:new", new('a', 64)),
            7, Now, "0.2.900", true, snapshot => retained = AgentUpdateLocalService.PreserveClosedLabFailure(root, snapshot)));
        Assert.Equal(original, AgentUpdateDurableFile.Read<AgentUpdateJournal>(retained!, root));
        Assert.Equal(policy.CampaignId, store.Read().InstallRequest!.LocalPolicyId);
    }

    [Theory]
    [InlineData("bound")]
    [InlineData("verified-release")]
    [InlineData("installer-result")]
    [InlineData("downloading")]
    [InlineData("awaiting-consent")]
    [InlineData("generation")]
    [InlineData("plan_mismatch")]
    [InlineData("release_unavailable")]
    [InlineData("expired")]
    public void StagingFailureThatMayHaveProgressedCannotBeHandedOver(string changed)
    {
        var closed = GaveUpStaging(); var request = closed.InstallRequest!;
        var failed = changed switch
        {
            "bound" => closed with { InstallRequest = request with { BoundAttemptId = closed.AttemptId } },
            "verified-release" => closed with { InstallRequest = request with { VerifiedRelease = request.ExpectedPlan } },
            "installer-result" => closed with { InstallerResult = ClosedForeignFailure().InstallerResult! with { AttemptId = closed.AttemptId } },
            "downloading" => closed with { Phase = AgentUpdateStates.Downloading },
            "awaiting-consent" => closed with { Phase = AgentUpdateStates.AwaitingConsent },
            "generation" => closed with { LifecycleGeneration = 8 },
            _ => closed with { InstallRequest = request with { TerminalReason = changed } },
        };
        Assert.False(AgentUpdateLocalService.CanContinueLabCampaign(failed, Policy(), "0.2.900", true));
        Assert.Same(failed, AgentUpdateLocalService.AdmitLabInstallRequest(failed, Policy(), new("0.2.901", "dev:new", new('a', 64)),
            7, Now, "0.2.900", true, _ => throw new InvalidOperationException("Invalid predecessors cannot write receipts.")));
    }

    // Three staging tries ran out while the download was paused; the request was never bound to an attempt.
    private static AgentUpdateJournal GaveUpStaging() => new()
    {
        Phase = AgentUpdateStates.Failed, AttemptId = "52e9ac8124e6462798d76bc129a364c0", LifecycleGeneration = 7,
        HealthyInstalledVersion = "0.2.900", HealthyInstalledSequence = 42,
        InstallRequest = new AgentUpdateInstallRequest(Now.AddHours(-2), 7, Now.AddHours(1), Attempts: 3,
            ExpectedPlan: new("0.2.941", "dev:failed", new('b', 64)), TerminalReason: "staging_failed", TerminalUtc: Now.AddHours(-1),
            TerminalJournalPhase: AgentUpdateStates.Failed, TerminalJournalAttemptId: "a0c950fcba90401890bec7511ba0c17c",
            LocalPolicyId: "d317377e-5553-43cf-9404-bfcb0a236733", LocalSourceVersion: "0.2.940"),
    };

    // The updater's own failure path, after a busy installer exited and before the next launch fence was written.
    private static AgentUpdateJournal PreLaunchUpdaterFailure()
    {
        var failed = ClosedForeignFailure();
        return failed with { InstallerBusyCount = 1, InstallerResult = failed.InstallerResult! with
            { ErrorCode = "unknown", MsiExitCode = null, ErrorMessage = "Updater requires recovery." } };
    }

    internal static AgentUpdateJournal ClosedForeignFailure()
    {
        const string attempt = "806f2475f85d416aa1ad7b10bfd9069b";
        var plan = new AgentUpdateExpectedPlan("0.2.941", "dev:failed", new('b', 64));
        return new AgentUpdateJournal
        {
            Phase = AgentUpdateStates.Failed, AttemptId = attempt, LifecycleGeneration = 7,
            HealthyInstalledVersion = "0.2.901", HealthyInstalledSequence = 42, FailedInstallSequence = 43,
            RunnerProcessId = 6812, InstallerProcessId = 3924, RunnerStartedUtc = Now.AddHours(-2),
            InstallRequest = new AgentUpdateInstallRequest(Now.AddHours(-2), 7, Now.AddHours(1), Attempts: 1,
                ExpectedPlan: plan, BoundAttemptId: attempt, VerifiedRelease: plan, TerminalReason: "attempt_failed",
                TerminalUtc: Now.AddHours(-1), TerminalJournalPhase: AgentUpdateStates.Failed, TerminalJournalAttemptId: attempt,
                LocalPolicyId: "d317377e-5553-43cf-9404-bfcb0a236733", LocalSourceVersion: "0.2.940"),
            InstallerResult = new AgentUpdateInstallerResult(AgentUpdateInstallerResult.CurrentSchemaVersion, "failure-result",
                AgentUpdateStates.Failed, Now.AddHours(-1).ToString("O"), 1603, false, "msi_failed", null, null, attempt)
        };
    }

    [Fact]
    public async Task CommittedNewBootstrapHandsOverCompletedOlderCampaignWithoutResettingHistory()
    {
        var policy = Policy(); var identity = Identity(); var transaction = Guid.NewGuid().ToString("D");
        var ledger = new AgentUpdateLabRuntimeAdmission.BootstrapLedger(policy.CampaignId, "policy-hash", identity, transaction, "0.2.1010", "pending");
        var scope = new AgentUpdateLabRuntime.Scope(policy, policy.Targets[0], identity);
        var previousPlan = new AgentUpdateExpectedPlan("0.2.1010", "dev:previous", new('b', 64));
        var previous = new AgentUpdateInstallRequest(Now.AddHours(-1), 7, Now.AddMinutes(30), Attempts: 2,
            ExpectedPlan: previousPlan, BoundAttemptId: new('b', 32), VerifiedRelease: previousPlan,
            TerminalReason: "installed", TerminalUtc: Now.AddMinutes(-10), LocalPolicyId: Guid.NewGuid().ToString("D"),
            LocalSourceVersion: "0.2.1009");
        var original = new AgentUpdateJournal { Phase = AgentUpdateStates.Installed, AttemptId = previous.BoundAttemptId,
            InstallRequest = previous, HealthyInstalledVersion = "0.2.1010", HealthyInstalledSequence = 42, FailedInstallSequence = 41 };
        var journal = original;
        var release = new AgentUpdateExpectedPlan("0.2.901", "dev:new", new('a', 64));
        var admissions = 0;
        Task Admit(CancellationToken _)
        {
            admissions++;
            var committed = AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(ledger, policy, identity, "policy-hash");
            journal = AgentUpdateLocalService.AdmitLabInstallRequest(journal, policy, release, 7, Now, "0.2.900+installed", committed);
            return Task.CompletedTask;
        }
        Task<bool> Tick() => AgentUpdateLocalService.RunLabTickAfterBootstrapAsync(scope,
            s => AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(ledger, s.Policy, s.Context, "policy-hash"), Admit, default);
        Assert.False(await Tick());
        Assert.Same(original, journal);
        Assert.Equal(0, admissions);
        ledger = AgentUpdateLabRuntimeAdmission.CommitBootstrap(ledger, policy, identity, transaction, "policy-hash");
        Assert.True(await Tick());
        Assert.Equal(policy.CampaignId, journal.InstallRequest!.LocalPolicyId);
        Assert.Equal("0.2.901", journal.InstallRequest.ExpectedPlan!.Version);
        Assert.Equal("0.2.900", journal.InstallRequest.LocalSourceVersion);
        Assert.Equal(policy.ExpiresAtUtc, journal.InstallRequest.ExpiresUtc);
        Assert.Equal(42, journal.HealthyInstalledSequence);
        Assert.Equal(41, journal.FailedInstallSequence);
        Assert.Equal(previous, original.InstallRequest);
        Assert.Equal(2, original.InstallRequest!.Attempts);
        var admitted = journal;
        Assert.True(await Tick());
        Assert.Same(admitted, journal); // A pending new request is never replaced with a fresh budget/deadline.

        Assert.Same(original, AgentUpdateLocalService.AdmitLabInstallRequest(original, policy, release, 7, Now, "0.2.900"));
        var pendingOld = original with { InstallRequest = previous with { BoundAttemptId = null, TerminalReason = null, TerminalUtc = null } };
        Assert.Same(pendingOld, AgentUpdateLocalService.AdmitLabInstallRequest(pendingOld, policy, release, 7, Now, "0.2.900", true));
        foreach (var reason in new string?[] { null, "attempt_failed", "staging_failed", "expired", "lifecycle_changed" })
        {
            var blocked = original with { InstallRequest = previous with { TerminalReason = reason } };
            Assert.Same(blocked, AgentUpdateLocalService.AdmitLabInstallRequest(blocked, policy, release, 7, Now, "0.2.900", true));
        }
        foreach (var phase in new[] { AgentUpdateStates.Failed, AgentUpdateStates.Quarantined, AgentUpdateStates.Blocked })
        {
            var blocked = original with { Phase = phase };
            Assert.Same(blocked, AgentUpdateLocalService.AdmitLabInstallRequest(blocked, policy, release, 7, Now, "0.2.900", true));
        }
        Assert.Same(original, AgentUpdateLocalService.AdmitLabInstallRequest(original, policy,
            release with { Version = "0.2.902" }, 7, Now, "0.2.901", true));
        Assert.Same(original, AgentUpdateLocalService.AdmitLabInstallRequest(original, policy, release, 7, policy.ExpiresAtUtc, "0.2.900", true));
        var replay = original with { InstallRequest = previous with { ExpectedPlan = release, VerifiedRelease = release } };
        Assert.Same(replay, AgentUpdateLocalService.AdmitLabInstallRequest(replay, policy, release, 7, Now, "0.2.900", true));
        var alreadyCurrent = original with { InstallRequest = previous with { TerminalReason = "current" } };
        Assert.Equal(policy.CampaignId, AgentUpdateLocalService.AdmitLabInstallRequest(alreadyCurrent, policy,
            release, 7, Now, "0.2.900", true).InstallRequest!.LocalPolicyId);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("nonce")]
    [InlineData("agent")]
    [InlineData("tenant")]
    [InlineData("key")]
    public async Task NewCampaignCannotUseAnotherCommittedBootstrapContext(string changed)
    {
        var policy = Policy(); var identity = Identity();
        var ledger = new AgentUpdateLabRuntimeAdmission.BootstrapLedger(policy.CampaignId, "policy-hash", identity,
            Guid.NewGuid().ToString("D"), "0.2.1010", "committed");
        var other = changed switch
        {
            "generation" => identity with { Generation = identity.Generation + 1 },
            "nonce" => identity with { EnrollmentNonce = "another-enrollment" },
            "agent" => identity with { AgentId = "another-agent" },
            "tenant" => identity with { TenantId = "another-tenant" },
            "key" => identity with { KeyFingerprint = "sha256:" + new string('c', 64) },
            _ => throw new InvalidOperationException()
        };
        var called = false;
        var scope = new AgentUpdateLabRuntime.Scope(policy, policy.Targets[0], other);
        await Assert.ThrowsAsync<InvalidOperationException>(() => AgentUpdateLocalService.RunLabTickAfterBootstrapAsync(scope,
            s => AgentUpdateLabRuntimeAdmission.IsBootstrapCommitted(ledger, s.Policy, s.Context, "policy-hash"),
            _ => { called = true; return Task.CompletedTask; }, default));
        Assert.False(called);
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
#endif
