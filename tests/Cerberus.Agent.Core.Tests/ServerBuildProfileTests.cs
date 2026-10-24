// Build-profile tests. The test project inherits DefineConstants from Directory.Build.props, so:
//   dotnet test ... -c Release                              -> default build (#if !CERBERUS_SERVER_PROFILE blocks)
//   dotnet test ... -c Release -p:AgentBuildProfile=server  -> server profile (#if CERBERUS_SERVER_PROFILE blocks)
// Blocks outside #if (key fingerprint, recovery policy and runner) run in both builds.
using System.Security.Cryptography;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Core.Tests;

public sealed class ServerBuildProfileTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-06-02T00:00:00Z");

    // ---- Build switch -------------------------------------------------------------------

    [Fact]
    public void BuildProfile_FollowsCompileConstant()
    {
#if CERBERUS_SERVER_PROFILE
        Assert.True(AgentBuildProfile.IsServer);
#else
        Assert.False(AgentBuildProfile.IsServer);
#endif
    }

    // ---- Item 5: key fingerprint (both builds) ------------------------------------------

    [Fact]
    public void KeyFingerprint_IsSha256PrefixedLowercaseHexOfSpki()
    {
        using var rsa = RSA.Create(2048);
        var spki = rsa.ExportSubjectPublicKeyInfo();

        var fromPem = AgentKeyFingerprint.FromPrivateKeyPem(rsa.ExportPkcs8PrivateKeyPem());
        var fromSpki = AgentKeyFingerprint.FromSubjectPublicKeyInfo(spki);

        Assert.Equal(fromSpki, fromPem);
        Assert.Matches("^sha256:[0-9a-f]{64}$", fromPem);
        Assert.Equal("sha256:" + Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant(), fromPem);
    }

    [Fact]
    public void KeyFingerprint_MalformedPemYieldsNullWithoutThrowing()
    {
        Assert.Null(AgentKeyFingerprint.TryFromPrivateKeyPem("not a pem"));
    }

    // ---- Item 4: dormant recovery policy (both builds) ----------------------------------

    [Theory]
    [InlineData(AgentLifecycleState.AuthSuspect, null, true, true)]
    [InlineData(AgentLifecycleState.BlockedConfig, null, true, true)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, null, true, true)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_missing", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_unavailable", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_invalid", true, false)]
    [InlineData(AgentLifecycleState.AuthSuspect, "credentials_invalid", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch", true, true)]
    [InlineData(AgentLifecycleState.AuthSuspect, "auth_suspect", true, true)]
    [InlineData(AgentLifecycleState.Retired, null, true, false)]
    [InlineData(AgentLifecycleState.Active, null, true, false)]
    [InlineData(AgentLifecycleState.Degraded, null, true, false)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_deactivated", true, false)]
    [InlineData(AgentLifecycleState.AuthSuspect, "agent_revoked", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, null, false, false)]
    public void Recovery_IsRecoverable_OnlyForNonTerminalDormantStatesWithQuiescence(
        AgentLifecycleState state, string? reason, bool quiescent, bool expected)
    {
        var snapshot = new AgentLifecycleSnapshot(state, reason) { QuiescenceComplete = quiescent };
        Assert.Equal(expected, AgentDormantRecoveryPolicy.IsRecoverable(snapshot));
    }

    [Fact]
    public void Recovery_Backoff_StartsAt15MinutesDoublesAndCapsAt6Hours()
    {
        var noJitter = new AgentDormantRecoveryPolicy(() => Now, () => 1d);
        Assert.Equal(TimeSpan.FromMinutes(15), noJitter.DelayFor(0));
        Assert.Equal(TimeSpan.FromMinutes(30), noJitter.DelayFor(1));
        Assert.Equal(TimeSpan.FromMinutes(60), noJitter.DelayFor(2));
        Assert.Equal(TimeSpan.FromHours(6), noJitter.DelayFor(5));
        Assert.Equal(TimeSpan.FromHours(6), noJitter.DelayFor(1000));
        Assert.Equal(TimeSpan.FromMinutes(15), noJitter.DelayFor(-3));
    }

    [Theory]
    [InlineData(0d)]
    [InlineData(0.5d)]
    [InlineData(1d)]
    [InlineData(7d)]
    [InlineData(-2d)]
    public void Recovery_Jitter_StaysWithin75To100PercentAndNeverAboveCap(double random)
    {
        var policy = new AgentDormantRecoveryPolicy(() => Now, () => random);
        for (var attempt = 0; attempt <= 40; attempt++)
        {
            var unjittered = new AgentDormantRecoveryPolicy(() => Now, () => 1d).DelayFor(attempt);
            var delay = policy.DelayFor(attempt);
            Assert.True(delay >= unjittered * 0.75 - TimeSpan.FromMilliseconds(1), $"attempt {attempt}: {delay}");
            Assert.True(delay <= unjittered, $"attempt {attempt}: {delay}");
            Assert.True(delay <= TimeSpan.FromHours(6));
        }
    }

    [Fact]
    public void Recovery_Schedule_PersistsNextAttemptTimeAndAttemptCount()
    {
        var policy = new AgentDormantRecoveryPolicy(() => Now, () => 1d);
        var scheduled = policy.Schedule(new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect), 2);

        Assert.Equal(Now + TimeSpan.FromMinutes(60), scheduled.NextAttemptUtc);
        Assert.Equal(2, scheduled.TransientFailureCount);
        Assert.False(policy.IsDue(scheduled));
        Assert.True(new AgentDormantRecoveryPolicy(() => Now.AddMinutes(60), () => 1d).IsDue(scheduled));
    }

    // ---- Item 4: dormant recovery runner (both builds) ----------------------------------

    [Fact]
    public async Task Recovery_FirstObservation_SchedulesFirstProbeWithoutProbing()
    {
        var (store, probes, run) = Harness(new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect), probeResult: true);

        var after = await run();

        Assert.Equal(0, probes.Count);
        Assert.Equal(AgentLifecycleState.AuthSuspect, after.State);
        Assert.Equal(Now + TimeSpan.FromMinutes(15), after.NextAttemptUtc);
        Assert.Equal(Now + TimeSpan.FromMinutes(15), (await store.LoadAsync(default)).NextAttemptUtc);
    }

    [Fact]
    public async Task Recovery_NotDue_DoesNotProbe()
    {
        var (_, probes, run) = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.BlockedConfig, NextAttemptUtc: Now.AddMinutes(1)), probeResult: true);

        var after = await run();

        Assert.Equal(0, probes.Count);
        Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
    }

    [Fact]
    public async Task Recovery_FailedProbe_PersistsLongerBackoffAndStaysDormant()
    {
        var (store, probes, run) = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.NeedsReenrollment, NextAttemptUtc: Now.AddSeconds(-1)),
            probeResult: false);

        var first = await run();
        Assert.Equal(1, probes.Count);
        Assert.Equal(AgentLifecycleState.NeedsReenrollment, first.State);
        Assert.Equal(1, first.TransientFailureCount);
        Assert.Equal(Now + TimeSpan.FromMinutes(30), first.NextAttemptUtc);
        Assert.Equal(first.NextAttemptUtc, (await store.LoadAsync(default)).NextAttemptUtc);
    }

    [Fact]
    public async Task Recovery_ThrowingProbe_IsTreatedAsFailure()
    {
        var (_, probes, run) = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)),
            probeResult: false, probeThrows: true);

        var after = await run();

        Assert.Equal(1, probes.Count);
        Assert.Equal(AgentLifecycleState.AuthSuspect, after.State);
        Assert.Equal(1, after.TransientFailureCount);
    }

    [Theory]
    [InlineData(AgentLifecycleState.NeedsReenrollment)]
    [InlineData(AgentLifecycleState.AuthSuspect)]
    [InlineData(AgentLifecycleState.BlockedConfig)]
    public async Task Recovery_SuccessfulProbe_ReturnsToActiveAndClearsSchedule(AgentLifecycleState state)
    {
        var (store, probes, run) = Harness(
            new AgentLifecycleSnapshot(state, NextAttemptUtc: Now.AddSeconds(-1)) { TransientFailureCount = 3 },
            probeResult: true);

        var after = await run();

        Assert.Equal(1, probes.Count);
        Assert.Equal(AgentLifecycleState.Active, after.State);
        Assert.Null(after.NextAttemptUtc);
        Assert.Equal(0, after.TransientFailureCount);
        Assert.Equal(AgentLifecycleState.Active, (await store.LoadAsync(default)).State);
    }

    [Theory]
    [InlineData(AgentLifecycleState.Retired, null)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_deactivated")]
    [InlineData(AgentLifecycleState.AuthSuspect, "agent_revoked")]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required")]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_missing")]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_unavailable")]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_invalid")]
    [InlineData(AgentLifecycleState.Active, null)]
    public async Task Recovery_TerminalOrActiveStates_NeverProbeNorSchedule(AgentLifecycleState state, string? reason)
    {
        var initial = new AgentLifecycleSnapshot(state, reason, NextAttemptUtc: Now.AddSeconds(-1));
        var (store, probes, run) = Harness(initial, probeResult: true);

        var after = await run();

        Assert.Equal(0, probes.Count);
        Assert.Equal(state, after.State);
        Assert.Equal(initial.NextAttemptUtc, (await store.LoadAsync(default)).NextAttemptUtc);
    }

    [Fact]
    public async Task Recovery_PendingQuiescenceOrAdoption_DoesNotProbe()
    {
        var pending = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)) { QuiescenceComplete = false },
            probeResult: true);
        await pending.Run();
        Assert.Equal(0, pending.Probes.Count);

        var adopting = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect, NextAttemptUtc: Now.AddSeconds(-1)),
            probeResult: true, awaitingAdoption: true);
        await adopting.Run();
        Assert.Equal(0, adopting.Probes.Count);
    }

    [Fact]
    public async Task Recovery_ScheduledCompletion_IgnoresChangedGeneration()
    {
        var store = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.NeedsReenrollment));
        var controller = new AgentLifecycleController(store);

        var result = await controller.CompleteScheduledRecoveryAsync(expectedGeneration: 99, default);

        Assert.Equal(AgentLifecycleState.NeedsReenrollment, result.State);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("backend_environment_mismatch")]
    public async Task Recovery_BlockedConfigWithoutCredentialOrReenrollReason_IsStillProbed(string? reason)
    {
        var (_, probes, run) = Harness(
            new AgentLifecycleSnapshot(AgentLifecycleState.BlockedConfig, reason, NextAttemptUtc: Now.AddSeconds(-1)),
            probeResult: true);

        var after = await run();

        Assert.Equal(1, probes.Count);
        Assert.Equal(AgentLifecycleState.Active, after.State);
    }

    private static (InMemoryAgentLifecycleStateStore Store, ProbeCounter Probes, Func<Task<AgentLifecycleSnapshot>> Run) Harness(
        AgentLifecycleSnapshot initial, bool probeResult, bool probeThrows = false, bool awaitingAdoption = false)
    {
        var store = new InMemoryAgentLifecycleStateStore(initial);
        var probes = new ProbeCounter();
        var policy = new AgentDormantRecoveryPolicy(() => Now, () => 1d);
        var controller = new AgentLifecycleController(store);
        async Task<AgentLifecycleSnapshot> Run()
        {
            var snapshot = await store.LoadAsync(default);
            return await DormantStateRecovery.RunAsync(store, controller, policy,
                (_, _) =>
                {
                    probes.Count++;
                    return probeThrows ? throw new HttpRequestException("probe") : Task.FromResult(probeResult);
                },
                snapshot, awaitingAdoption, NullAgentLogger.Instance, default);
        }
        return (store, probes, Run);
    }

    private sealed class ProbeCounter { public int Count; }

#if CERBERUS_SERVER_PROFILE
    // ---- Server profile only ------------------------------------------------------------

    private static readonly string[] ServerSections =
        { "os", "resources", "clock", "runtime", "firewall", "network", "security", "identity" };

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("tailscale,rdp,capabilities")]
    [InlineData("nonexistent")]
    public void Item2_Telemetry_ProfileSendsOnlyListedSections_IgnoringEnvAllowlist(string? configured)
    {
        var names = WindowsTelemetrySectionCatalog.CreateDefault(configured).Select(s => s.SectionName).ToArray();

        Assert.Equal(ServerSections.OrderBy(n => n), names.OrderBy(n => n));
        Assert.DoesNotContain("tailscale", names);
        Assert.DoesNotContain("rdp", names);
        Assert.DoesNotContain("capabilities", names);
    }

    [Fact]
    public void Item1_Claim_PendingClaimIsAcceptedButRejectedStatesAreNot()
    {
        Assert.True(AgentClaimGate.IsClaimed(Heartbeat("pending_claim", claimRequired: true)));
        Assert.True(AgentClaimGate.IsClaimed(Heartbeat(null, claimRequired: true)));
        Assert.True(AgentClaimGate.IsClaimed(Heartbeat("claimed")));
        foreach (var state in new[] { "rejected", "deactivated", "revoked" })
            Assert.False(AgentClaimGate.IsClaimed(Heartbeat(state)), state);
    }

    [Fact]
    public void Item1_Claim_LocalControlAcceptsPendingClaimButKeepsRevokedAndQuarantinedChecks()
    {
        Assert.True(AgentLocalControlService.Claimed(Heartbeat("pending_claim", claimRequired: true)));
        Assert.False(AgentLocalControlService.Claimed(Heartbeat("pending_claim", lifecycle: "revoked")));
        Assert.False(AgentLocalControlService.Claimed(Heartbeat("claimed", lifecycle: "quarantined")));
        Assert.False(AgentLocalControlService.Claimed(Heartbeat("revoked")));
    }

    [Fact]
    public void Item1_Claim_ServiceInstallDoesNotRequireClaim()
    {
        // The store is never touched: a claim check would dereference it.
        AgentClaimGate.RequireClaimedForServiceInstall(null!, default);
    }

    // ---- Backend address migration out of a persisted backend_environment_mismatch block ----
    // The compiled address is passed through the optional parameter; the positive case is server-profile only.

    private const string OldBackend = "https://old-collector.example.test:8443";

    private static async Task<(DpapiSecretStore Secrets, AgentLifecycleController Controller, InMemoryAgentLifecycleStateStore Store, AgentLifecycleSnapshot Blocked)>
        BlockedByMismatchAsync()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var secrets = new DpapiSecretStore(SecretStoreScope.User, dir);
        await secrets.SaveAsync(new AgentIdentity("agent-id-1", "tenant-id-1"), "refresh-1", "key-pem-1", OldBackend, null, null, default);
        var store = new InMemoryAgentLifecycleStateStore(
            new AgentLifecycleSnapshot(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch"));
        return (secrets, new AgentLifecycleController(store), store, await store.LoadAsync(default));
    }

#if CERBERUS_SERVER_PROFILE
    [Fact]
    public async Task Migration_CompiledHttpsAddressAndNoOverride_ActivatesAndKeepsIdentity()
    {
        const string compiled = "https://new-collector.example.test:8443";
        var (secrets, controller, store, blocked) = await BlockedByMismatchAsync();
        var saved = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL");
        Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", null);
        try
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(
                controller, secrets, blocked, awaitingAdoption: false, NullAgentLogger.Instance, default, compiled);

            Assert.Equal(AgentLifecycleState.Active, after.State);
            Assert.Equal(AgentLifecycleState.Active, (await store.LoadAsync(default)).State);
            var creds = await secrets.LoadAsync(default);
            Assert.Equal(compiled, creds.BackendUrl);
            Assert.Equal(new AgentIdentity("agent-id-1", "tenant-id-1"), creds.Identity);
            Assert.Equal("refresh-1", creds.RefreshToken);
            Assert.Equal("key-pem-1", creds.PrivateKeyPem);
        }
        finally { Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", saved); }
    }
#endif

    [Fact]
    public async Task Migration_CompiledHttpAddress_StaysDormantWithRegistrationUnchanged()
    {
        var (secrets, controller, store, blocked) = await BlockedByMismatchAsync();
        var saved = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL");
        Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", null);
        try
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(
                controller, secrets, blocked, awaitingAdoption: false, NullAgentLogger.Instance, default,
                "http://new-collector.example.test:8080");

            Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
            Assert.Equal(AgentLifecycleState.BlockedConfig, (await store.LoadAsync(default)).State);
            Assert.Equal(OldBackend, (await secrets.LoadAsync(default)).BackendUrl);
        }
        finally { Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", saved); }
    }

    [Fact]
    public async Task Migration_EnvironmentOverride_StaysDormantWithRegistrationUnchanged()
    {
        var (secrets, controller, store, blocked) = await BlockedByMismatchAsync();
        var saved = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL");
        Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", "https://override.example.test");
        try
        {
            var after = await DormantStateRecovery.TryMigrateBackendAsync(
                controller, secrets, blocked, awaitingAdoption: false, NullAgentLogger.Instance, default);

            Assert.Equal(AgentLifecycleState.BlockedConfig, after.State);
            Assert.Equal(AgentLifecycleState.BlockedConfig, (await store.LoadAsync(default)).State);
            Assert.Equal(OldBackend, (await secrets.LoadAsync(default)).BackendUrl);
        }
        finally { Environment.SetEnvironmentVariable("CERBERUS_BACKEND_URL", saved); }
    }

    [Theory]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_invalid", false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "some_other_block", false)]
    [InlineData(AgentLifecycleState.AuthSuspect, "backend_environment_mismatch", false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch", true)]
    public async Task Migration_OnlyActsOnBackendMismatchBlock_AndNotWhileAwaitingAdoption(
        AgentLifecycleState state, string reason, bool awaitingAdoption)
    {
        var (secrets, controller, _, _) = await BlockedByMismatchAsync();
        var snapshot = new AgentLifecycleSnapshot(state, reason);

        var after = await DormantStateRecovery.TryMigrateBackendAsync(
            controller, secrets, snapshot, awaitingAdoption, NullAgentLogger.Instance, default);

        Assert.Equal(state, after.State);
        Assert.Equal(OldBackend, (await secrets.LoadAsync(default)).BackendUrl);
    }

    [Fact]
    public async Task Item3_Diagnostics_UploadIsRefusedBeforeAnyRequest()
    {
        var called = false;
        var uploader = new AgentDiagnosticBundleUploader(Metadata(), (_, _) =>
        {
            called = true;
            return Task.FromResult(new AgentDiagnosticBundleAckResponse("accepted", "b", 1, 0, null));
        });
        var context = new AgentDiagnosticRequestContext("scheduled", null, null, null);

        await Assert.ThrowsAsync<InvalidOperationException>(() => uploader.UploadAsync(context, default));
        Assert.False(called);
    }

    [Fact]
    public async Task Item3_Diagnostics_SchedulerReturnsImmediatelyAndWritesNoState()
    {
        var path = Path.Combine(Path.GetTempPath(), $"cerberus-diag-scheduler-{Guid.NewGuid():N}.json");
        var called = false;
        var uploader = new AgentDiagnosticBundleUploader(Metadata(), (_, _) =>
        {
            called = true;
            return Task.FromResult(new AgentDiagnosticBundleAckResponse("accepted", "b", 1, 0, null));
        });
        var scheduler = new DiagnosticBundleScheduler(uploader, NullAgentLogger.Instance, statePath: path,
            interval: TimeSpan.Zero, maxJitter: TimeSpan.Zero, clock: () => Now);

        await scheduler.RunAsync(new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(called);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task Item3_Diagnostics_LocalExportIsRefused()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"cerberus-diag-{Guid.NewGuid():N}");
        await Assert.ThrowsAsync<InvalidOperationException>(() => AgentDiagnosticsBundle.ExportAsync(dir, dir));
        Assert.False(Directory.Exists(dir));
    }
#else
    // ---- Default build unchanged --------------------------------------------------------

    [Fact]
    public void Item2_Telemetry_DefaultStillSendsAllSectionsAndHonorsAllowlist()
    {
        var all = WindowsTelemetrySectionCatalog.CreateDefault((string?)null).Select(s => s.SectionName).ToArray();
        Assert.Contains("tailscale", all);
        Assert.Contains("rdp", all);
        Assert.Contains("capabilities", all);

        Assert.Equal(new[] { "tailscale" },
            WindowsTelemetrySectionCatalog.CreateDefault("tailscale").Select(s => s.SectionName).ToArray());
        Assert.Equal(all, WindowsTelemetrySectionCatalog.CreateDefault("nonexistent").Select(s => s.SectionName).ToArray());
    }

    [Fact]
    public void Item1_Claim_DefaultStillRequiresClaimedState()
    {
        Assert.False(AgentClaimGate.IsClaimed(Heartbeat("pending_claim", claimRequired: true)));
        Assert.False(AgentClaimGate.IsClaimed(Heartbeat("claimed", claimRequired: true)));
        Assert.True(AgentClaimGate.IsClaimed(Heartbeat("claimed")));
        Assert.False(AgentLocalControlService.Claimed(Heartbeat("pending_claim", claimRequired: true)));
        Assert.True(AgentLocalControlService.Claimed(Heartbeat("claimed")));
        Assert.False(AgentLocalControlService.Claimed(Heartbeat("claimed", lifecycle: "revoked")));
    }

    [Fact]
    public async Task Item3_Diagnostics_DefaultStillUploadsAndSchedulesState()
    {
        var called = false;
        var uploader = new AgentDiagnosticBundleUploader(Metadata(), (_, _) =>
        {
            called = true;
            return Task.FromResult(new AgentDiagnosticBundleAckResponse("accepted", "b", 1, 0, null));
        });
        await uploader.UploadAsync(new AgentDiagnosticRequestContext("scheduled", null, null, null), default);
        Assert.True(called);
    }
#endif

    private static HeartbeatResponse Heartbeat(string? registration, bool claimRequired = false, string? lifecycle = null)
        => new(
            PendingCommands: Array.Empty<AgentCommand>(),
            NextPollSeconds: 30,
            ServerTime: 0,
            ServerTimeUtc: null,
            CommandBatchSize: 1,
            NextSnapshotSeconds: 300,
            ConfigVersion: null,
            LifecycleState: lifecycle,
            RegistrationState: registration,
            ClaimRequired: claimRequired,
            ManifestVersion: null,
            ManagedAccountManifestHash: null,
            ManifestFreshUntil: null,
            RequireManifestBeforeUnlock: false,
            AgentStatus: null,
            VersionPolicy: null,
            Update: null,
            Revoke: null,
            Quarantine: null);

    private static AgentBuildMetadata Metadata() => new(
        AgentVersion: "1.2.3",
        BuildId: "build-1",
        BuildChannel: "dev",
        BootId: "boot-1",
        SupportedSchemaVersions: AgentSchemaVersions.All);
}
