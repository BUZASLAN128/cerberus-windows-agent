using System.Text;
using System.Text.Json;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateLabPolicyTests
{
    private static readonly DateTimeOffset Start = new(2026, 11, 4, 10, 0, 0, TimeSpan.Zero);
    private static readonly string PcKey = "sha256:" + new string('a', 64);
    private static readonly string VmKey = "sha256:" + new string('b', 64);
    private const string Feed = "https://feed.example.invalid:9445/updates/devtest/";

    [Fact]
    public void AbsentPolicyPreservesNormalBuildBehavior()
        => Assert.Null(AgentUpdateLabPolicy.Parse("", "preview", false, true));

    [Theory]
    [InlineData("preview", true, true)]
    [InlineData("stable", true, true)]
    [InlineData("dev", false, true)]
    [InlineData("dev", true, false)]
    public void ExplicitPolicyRequiresServerDevUnsignedBuild(string channel, bool unsigned, bool server)
        => Assert.Throws<InvalidOperationException>(() => AgentUpdateLabPolicy.Parse(Encode(Valid()), channel, unsigned, server));

    [Fact]
    public void BothEnrolledTargetsAreBoundToTheirOwnIdentityAndPublicKey()
    {
        var policy = Parse(Valid());
        Assert.Equal("pc", policy.RequireTarget(new("pc", "tenant"), PcKey, Start).AgentId);
        Assert.Equal("vm", policy.RequireTarget(new("vm", "tenant"), VmKey, Start.AddHours(1)).AgentId);
        Assert.Throws<InvalidOperationException>(() => policy.RequireTarget(new("third", "tenant"), PcKey, Start));
        Assert.Throws<InvalidOperationException>(() => policy.RequireTarget(new("pc", "other-tenant"), PcKey, Start));
        Assert.Throws<InvalidOperationException>(() => policy.RequireTarget(new("pc", "tenant"), VmKey, Start));
        Assert.Throws<InvalidOperationException>(() => policy.RequireTarget(new("pc", "tenant"), "invalid", Start));
    }

    [Fact]
    public void TimeWindowAndFrozenVersionSetAreEnforced()
    {
        var policy = Parse(Valid());
        Assert.Throws<InvalidOperationException>(() => policy.RequireTarget(new("pc", "tenant"), PcKey, Start.AddTicks(-1)));
        Assert.Throws<InvalidOperationException>(() => policy.RequireTarget(new("pc", "tenant"), PcKey, policy.ExpiresAtUtc));
        policy.RequireVersion("0.2.1012+source-head");
        policy.RequireVersion("0.2.1022");
        Assert.Throws<InvalidOperationException>(() => policy.RequireVersion("0.2.1023"));
        Assert.Throws<InvalidOperationException>(() => policy.RequireVersion("0.2.1011"));
    }

    [Fact]
    public void MalformedOrExpandedPolicyIsDenied()
    {
        var valid = Valid();
        AssertDenied(valid with { ExpiresAtUtc = Start.AddHours(49) });
        AssertDenied(valid with { ExpiresAtUtc = Start });
        AssertDenied(valid with { Targets = [valid.Targets[0]] });
        AssertDenied(valid with { Targets = [valid.Targets[0], valid.Targets[0]] });
        AssertDenied(valid with { Versions = ["0.2.1012"] });
        AssertDenied(valid with { Versions = Enumerable.Repeat("0.2.1012", 11).ToArray() });
        AssertDenied(valid with { Targets = [valid.Targets[0] with { ArtifactPrefix = "https://feed.example.invalid/updates/preview/" }, valid.Targets[1]] });
        AssertDenied(valid with { Targets = [valid.Targets[0] with { ManifestUrl = "http://feed.example.invalid/updates/devtest/pc/latest.json" }, valid.Targets[1]] });
        AssertDenied(valid with { Targets = [valid.Targets[0] with { ManifestUrl = Feed + "pc/latest.json?token=forbidden" }, valid.Targets[1]] });
    }

    [Fact]
    public void DuplicateOrUnknownJsonFieldsCannotAmbiguouslyChangeAuthority()
    {
        var json = JsonSerializer.Serialize(Valid(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var duplicate = json.Replace("\"campaignId\":", "\"campaignId\":\"00000000-0000-0000-0000-000000000001\",\"campaignId\":", StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabPolicy.Parse(EncodeJson(duplicate), "dev", true, true));
        var unknown = json.Insert(1, "\"ignoreAuthorization\":true,");
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabPolicy.Parse(EncodeJson(unknown), "dev", true, true));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabPolicy.Parse("not-base64", "dev", true, true));
    }

    private static AgentUpdateLabPolicy Valid() => new("agent.update.lab.v1", "f4c2ca30-78df-4b86-95d7-9381eebefbe3", Start,
        Start.AddHours(24),
        [new("pc", "tenant", PcKey, Feed + "pc/latest.json", Feed), new("vm", "tenant", VmKey, Feed + "vm106/latest.json", Feed)],
        Enumerable.Range(1012, 11).Select(v => $"0.2.{v}").ToArray(), "https://collector.example.invalid", "https://sso.invalid");

    [Fact]
    public void LocalCampaignIsNotASignedCommandAndCannotMixAuthoritySources()
    {
        var release = new AgentUpdateExpectedPlan("0.2.1013", "dev:43", new string('a', 64));
        var local = new AgentUpdateInstallRequest(Start, 7, Start.AddHours(1), ExpectedPlan: release,
            LocalPolicyId: Valid().CampaignId);
        Assert.True(local.IsValid());
        Assert.True(local.RetainsReceipt);
        Assert.False(local.IsCorrelated);
        Assert.False((local with { CommandId = "fake-command", CampaignId = "campaign", IdempotencyKey = "key" }).IsValid());
        Assert.False((local with { ExpectedPlan = null }).IsValid());
        Assert.False((local with { ExpiresUtc = Start }).IsValid());
        Assert.False(local.SameIdentity(local with { LocalPolicyId = Guid.NewGuid().ToString("D") }));
    }

    [Fact]
    public void RequiredPolicyConversionCannotExtendLocalCampaignDeadline()
    {
        var policy = Valid();
        var release = new AgentUpdateExpectedPlan("0.2.1013", "dev:43", new string('a', 64));
        var attempt = new string('a', 32);
        var request = new AgentUpdateInstallRequest(Start, 7, Start.AddHours(1), ExpectedPlan: release,
            LocalPolicyId: policy.CampaignId, BoundAttemptId: attempt, VerifiedRelease: release);
        var active = new AgentUpdateJournal { Phase = AgentUpdateStates.AwaitingConsent, AttemptId = attempt,
            LifecycleGeneration = 7, InstallRequest = request, InstallRequestAuthorityExpiresUtc = request.ExpiresUtc };
        var converted = AgentUpdateLocalService.TransitionVerifiedRequiredPolicy(active, true, 7, 7, Start.AddMinutes(5));
        Assert.Null(converted.InstallRequestAuthorityExpiresUtc);
        Assert.Equal(7, converted.RequiredPolicyGeneration);
        Assert.Same(request, converted.InstallRequest);
        var scope = new AgentUpdateLabRuntime.Scope(policy, policy.Targets[0], new("pc", "tenant", 7, null, AgentProducts.Cerberus, PcKey));
        AgentUpdateLabRuntime.RequireLaunchScope(scope, converted, 7, Start.AddMinutes(30));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntime.RequireLaunchScope(scope, converted, 7, Start.AddHours(2)));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntime.RequireLaunchScope(scope, converted, 8, Start.AddMinutes(30)));
    }

    [Fact]
    public void EveryCountedTransitionHasOneSelectedLocalFaultAndBootstrapHasNone()
    {
        var policy = Valid();
        Assert.False(AgentUpdateLabFaults.UsesServiceInterruption(policy, policy.Versions[0]));
        for (var index = 1; index <= 10; index++)
            Assert.Equal(index != 8, AgentUpdateLabFaults.UsesServiceInterruption(policy, policy.Versions[index]));
    }

    [Fact]
    public async Task PreDownloadServiceRestartUsesExistingRecoveryAndRetainsRequestBudgetAndDeadline()
    {
        var now = DateTimeOffset.UtcNow;
        var release = new AgentUpdateExpectedPlan("0.2.1013", "dev:43", new string('a', 64));
        var request = new AgentUpdateInstallRequest(now.AddMinutes(-1), 7, now.AddHours(1), Attempts: 1,
            ExpectedPlan: release, LocalPolicyId: Valid().CampaignId);
        var interrupted = AgentUpdateLocalService.TransitionStageStart(new() { InstallRequest = request }, true, false, 7, now.AddDays(1));
        Assert.Null(interrupted.AttemptId); // The real interruption point precedes artifact attempt creation.
        var journal = AgentUpdateLocalService.TransitionInterruptedPreInstallWithoutAttempt(interrupted, 7, now);
        Assert.Same(request, journal.InstallRequest);
        Assert.Equal(AgentUpdateLocalService.InstallRequestStep.Run,
            AgentUpdateLocalService.NextInstallRequestStep(journal, 7, true, now));
        await AgentUpdateLocalService.RunInstallRequestAsync(journal, 7, true, change => journal = change(journal), _ =>
        {
            journal = journal with { Phase = AgentUpdateStates.AwaitingConsent, AttemptId = new string('a', 32),
                InstallRequest = journal.InstallRequest! with { VerifiedRelease = release } };
            return Task.FromResult(true);
        }, NullAgentLogger.Instance, default);
        Assert.Equal(1, journal.InstallRequest!.Attempts);
        Assert.Equal(request.ExpiresUtc, journal.InstallRequest.ExpiresUtc);
        Assert.Equal(request.LocalPolicyId, journal.InstallRequest.LocalPolicyId);
        Assert.Equal(journal.AttemptId, journal.InstallRequest.BoundAttemptId);
    }

    [Fact]
    public void MsiContinuationDoesNotRenewAdmissionOrAcceptChangedIdentityTransactionOrPayload()
    {
        var policy = Valid();
        var identity = new AgentStateDeliveryContext("pc", "tenant", 7, null, AgentProducts.Cerberus, PcKey);
        var product = Guid.NewGuid();
        var transaction = Guid.NewGuid().ToString("D");
        var receipt = new AgentUpdateLabRuntimeAdmission.Admission(policy.CampaignId, transaction, product.ToString("D"),
            policy.Versions[1], "policy-hash", "payload-hashes", identity, Start.AddMinutes(5), "attempt", new string('a', 64));
        Assert.Throws<InvalidOperationException>(() => policy.RequireTarget(new("pc", "tenant", AgentProducts.Cerberus), PcKey, policy.ExpiresAtUtc));
        // Continuation consumes the original admitted time; it does not consult/replace it with a later clock value.
        void Check(AgentUpdateLabRuntimeAdmission.Admission value) => AgentUpdateLabRuntimeAdmission.RequireContinuation(value,
            policy, product, policy.Versions[1], transaction, identity, "policy-hash", "payload-hashes");
        Check(receipt);
        Assert.Throws<InvalidOperationException>(() => Check(receipt with { Completed = true }));
        Assert.Throws<InvalidOperationException>(() => Check(receipt with { TransactionId = Guid.NewGuid().ToString("D") }));
        Assert.Throws<InvalidOperationException>(() => Check(receipt with { Identity = identity with { Generation = 8 } }));
        Assert.Throws<InvalidOperationException>(() => Check(receipt with { Identity = identity with { KeyFingerprint = VmKey } }));
        Assert.Throws<InvalidOperationException>(() => Check(receipt with { RuntimeHashesBase64 = "other-payload" }));
        Assert.Throws<InvalidOperationException>(() => Check(receipt with { AdmittedUtc = policy.ExpiresAtUtc }));
    }

    [Fact]
    public void RuntimeHashMetadataPreservesLocalizedPathsAndRejectsTraversalAndDuplicates()
    {
        var hashes = new Dictionary<string, string> { ["Cerberus.Agent.exe"] = new('a', 64),
            ["Cerberus.Agent.Service.exe"] = new('b', 64), ["Cerberus.Agent.Updater.exe"] = new('c', 64),
            ["tr/Cerberus.Agent.resources.dll"] = new('d', 64) };
        string Encoded() => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(JsonSerializer.Serialize(hashes)));
        Assert.Equal(4, AgentUpdateLabRuntimeAdmission.ParseHashes(Encoded()).Count);
        hashes["../Cerberus.Agent.Core.dll"] = new('e', 64);
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.ParseHashes(Encoded()));
        hashes.Remove("../Cerberus.Agent.Core.dll");
        hashes["cerberus.agent.exe"] = new('e', 64);
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLabRuntimeAdmission.ParseHashes(Encoded()));
    }

    [Fact]
    public void AdmissionCapsExpiryPreservesOtherRequestsAndDoesNotResetFailedRecovery()
    {
        var policy = Valid();
        var release = new AgentUpdateExpectedPlan("0.2.1013", "dev:43", new string('a', 64));
        var admitted = AgentUpdateLocalService.AdmitLabInstallRequest(new(), policy, release, 7, Start.AddHours(1));
        Assert.Equal(policy.ExpiresAtUtc, admitted.InstallRequest!.ExpiresUtc);
        var pending = AgentUpdateLocalService.AdmitLabInstallRequest(admitted, policy, release, 7, Start.AddHours(2));
        Assert.Same(admitted, pending);
        var failed = admitted with { InstallRequest = admitted.InstallRequest with { Attempts = 3,
            TerminalReason = "staging_failed", TerminalUtc = Start.AddHours(2) } };
        Assert.Same(failed, AgentUpdateLocalService.AdmitLabInstallRequest(failed, policy, release, 7, Start.AddHours(3)));
        Assert.Same(failed, AgentUpdateLocalService.AdmitLabInstallRequest(failed, policy,
            release with { Version = "0.2.1014", ReleaseId = "dev:44" }, 7, Start.AddHours(3)));
        Assert.Null(AgentUpdateLocalService.AdmitLabInstallRequest(new(), policy, release, 7, policy.ExpiresAtUtc).InstallRequest);
    }

    [Fact]
    public async Task InMemorySchedulerKeepsLocalCampaignReceiptAndDeadlineAfterStaging()
    {
        var now = DateTimeOffset.UtcNow;
        var policy = Valid() with { NotBeforeUtc = now.AddMinutes(-1), ExpiresAtUtc = now.AddHours(1) };
        var release = new AgentUpdateExpectedPlan("0.2.1013", "dev:43", new string('a', 64));
        var journal = AgentUpdateLocalService.AdmitLabInstallRequest(new(), policy, release, 7, now.AddSeconds(-1));
        var deadline = journal.InstallRequest!.ExpiresUtc;
        var handled = await AgentUpdateLocalService.RunInstallRequestAsync(journal, 7, true,
            change => journal = change(journal), _ =>
            {
                journal = journal with { Phase = AgentUpdateStates.AwaitingConsent, AttemptId = new string('a', 32),
                    LifecycleGeneration = 7, InstallRequest = journal.InstallRequest! with { VerifiedRelease = release } };
                return Task.FromResult(true);
            }, NullAgentLogger.Instance, default);
        Assert.True(handled);
        Assert.NotNull(journal.InstallRequest);
        Assert.Equal(journal.AttemptId, journal.InstallRequest.BoundAttemptId);
        Assert.Equal(policy.CampaignId, journal.InstallRequest.LocalPolicyId);
        Assert.Equal(deadline, journal.InstallRequestAuthorityExpiresUtc);
        Assert.Null(journal.RequiredPolicyGeneration);
        Assert.Equal(journal.AttemptId, journal.RequiredInstallAttemptId);
        Assert.Null(journal.InstallRequest.CommandId);
    }

    private static string Encode(AgentUpdateLabPolicy policy)
        => EncodeJson(JsonSerializer.Serialize(policy, new JsonSerializerOptions(JsonSerializerDefaults.Web)));

    [Fact]
    public void RetiredRunnerCannotOwnAReplacementLaunchOrChangeItsState()
    {
        var release = new AgentUpdateExpectedPlan("0.2.1020", "dev:50", new string('a', 64));
        var request = new AgentUpdateInstallRequest(Start, 7, Start.AddHours(1), ExpectedPlan: release,
            LocalPolicyId: Valid().CampaignId, BoundAttemptId: new string('a', 32), VerifiedRelease: release);
        var a = new AgentUpdateJournal { Phase = "launch_requested", AttemptId = new string('a', 32), RunnerProcessId = 100,
            RunnerStartedUtc = Start, RetryCount = 1, InstallRequest = request, LifecycleGeneration = 7 };
        var retired = AgentUpdateLocalService.RetryUnstartedLabRunner(a, a);
        Assert.Equal(AgentUpdateStates.RetryableBusy, retired.Phase);
        Assert.Equal(1, retired.RetryCount);
        Assert.Same(request, retired.InstallRequest);
        Assert.Null(retired.RunnerProcessId);
        var b = retired with { Phase = "launch_requested", RunnerProcessId = 200, RunnerStartedUtc = Start.AddSeconds(2) };
        Assert.False(AgentUpdateRunnerFiles.OwnsLaunch(b, a.AttemptId, 100, Start));
        Assert.True(AgentUpdateRunnerFiles.OwnsLaunch(b, a.AttemptId, 200, Start.AddSeconds(2)));
        Assert.False(AgentUpdateRunnerFiles.OwnsLaunch(b, a.AttemptId, 200, Start));
        Assert.Same(b, AgentUpdateLocalService.RetryUnstartedLabRunner(b, a));
        var crossedFence = a with { Phase = "install_may_have_started" };
        Assert.Same(crossedFence, AgentUpdateLocalService.RetryUnstartedLabRunner(crossedFence, a));
        Assert.Same(crossedFence, AgentUpdateLocalService.RetryUnstartedLabRunner(crossedFence, crossedFence));
        Assert.True(AgentUpdateLocalService.IsRunnerLockContention(unchecked((int)0x80070020)));
        Assert.False(AgentUpdateLocalService.IsRunnerLockContention(unchecked((int)0x80070005)));
    }

    private static string EncodeJson(string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    private static AgentUpdateLabPolicy Parse(AgentUpdateLabPolicy policy) => AgentUpdateLabPolicy.Parse(Encode(policy), "dev", true, true)!;
    private static void AssertDenied(AgentUpdateLabPolicy policy)
        => Assert.Throws<InvalidOperationException>(() => Parse(policy));
}
