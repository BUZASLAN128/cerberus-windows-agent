// Build-profile tests. The test project inherits DefineConstants from Directory.Build.props, so:
//   dotnet test ... -c Release                              -> default build (#if !CERBERUS_SERVER_PROFILE blocks)
//   dotnet test ... -c Release -p:AgentBuildProfile=server  -> server profile (#if CERBERUS_SERVER_PROFILE blocks)
// Recovery policy, runner, supervisor and migration tests live in the Dormant*/ServerBackendMigration files.
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

#if CERBERUS_SERVER_PROFILE
    // ---- Server profile only ------------------------------------------------------------

    private static readonly string[] ServerSections =
        {
            "os", "resources", "clock", "runtime", "firewall", "network", "security", "identity",
            "sessions", "hardware", "services", "listening_ports", "updates", "software",
        };

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
    public void Item1_Claim_HeartbeatOkCountsAsClaimedWhateverTheUnsignedStatesSay()
    {
        var revoked = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>("""{"revoked":true}""");
        var quarantined = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>("""{"active":true}""");
        var responses = new[]
        {
            Heartbeat("pending_claim", claimRequired: true),
            Heartbeat(null, claimRequired: true),
            Heartbeat("claimed"),
            Heartbeat("rejected"),
            Heartbeat("deactivated"),
            Heartbeat("revoked"),
            Heartbeat("pending_claim", lifecycle: "revoked"),
            Heartbeat("claimed", lifecycle: "quarantined"),
            Heartbeat("claimed") with { Revoke = revoked, Quarantine = quarantined },
        };
        foreach (var response in responses)
        {
            Assert.True(AgentClaimGate.IsClaimed(response));
            Assert.True(AgentLocalControlService.Claimed(response));
        }
    }

    [Fact]
    public void Item1_Claim_ServiceInstallDoesNotRequireClaim()
    {
        // The store is never touched: a claim check would dereference it.
        AgentClaimGate.RequireClaimedForServiceInstall(null!, default);
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
