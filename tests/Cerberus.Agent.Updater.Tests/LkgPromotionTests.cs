using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed class LkgPromotionTests : IDisposable
{
    private const string Attempt = "watched-attempt";
    private const string Version = "1.2.1";
    private const string OldVersion = "1.2.0";
    private const string Pin = "test-pin";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-18T12:00:00Z");
    private readonly DirectoryInfo _temp = Directory.CreateTempSubdirectory("lkg-promotion-support-");
    private readonly AgentUpdateLkgStore _store;
    private readonly AgentUpdateBuildMetadata _metadata;
    private readonly AgentUpdatePlan _plan;
    private readonly AgentUpdateWatchRecord _watch;
    private readonly LkgPromotion.RuntimeIdentity _identity;
    private readonly List<string> _logs = [];
    private AgentUpdateJournal _journal = new()
    {
        AttemptId = Attempt,
        Phase = AgentUpdateWatchJournal.CommittedWatch,
        HealthyInstalledVersion = OldVersion,
        HealthyInstalledSequence = 40,
        LifecycleGeneration = 1,
    };

    public LkgPromotionTests()
    {
        _store = new AgentUpdateLkgStore(Path.Combine(_temp.FullName, "updates"));
        Directory.CreateDirectory(_store.Root);
        File.WriteAllText(_store.HostPath, "old updater");
        File.WriteAllText(_store.MsiPath, "old MSI");
        File.WriteAllText(_store.ManifestPath, "old manifest");
        File.WriteAllText(_store.RecordPath, "old metadata");
        AgentUpdateLkgStore.WriteRecord(_store.HostRecordPath, _store.UpdatesRoot, new AgentUpdateLkgHostRecord(
            AgentUpdateLkgStore.HostSchema, OldVersion, Hash(_store.HostPath), "bootstrap", Now, null, OldVersion));
        AgentUpdateRollbackFloor.Raise(_store.UpdatesRoot, OldVersion, "watch_pass", 40, new string('a', 64), Now);

        var runtime = _temp.CreateSubdirectory("runtime").FullName;
        var service = Path.Combine(runtime, "Cerberus.Agent.Service.exe");
        File.WriteAllText(service, "watched service");
        File.WriteAllText(Path.Combine(runtime, AgentUpdateLkgStore.UpdaterFileName), "new updater");
        _identity = new(Version, Guid.NewGuid(), Hash(service), runtime);

        var attempt = Path.Combine(_store.UpdatesRoot, "attempts", "attempt-" + Attempt);
        Directory.CreateDirectory(attempt);
        var msi = Path.Combine(attempt, AgentUpdateSecurity.ArtifactFileName);
        var storedManifest = Path.Combine(attempt, AgentUpdateSecurity.ManifestFileName);
        File.WriteAllText(msi, "new MSI");
        using var fixtureKey = RSA.Create(2048);
        var manifest = new AgentUpdateManifest("msi", Version, "dev", "https://example.invalid/agent.msi", Hash(msi),
            "fixture signer", "2026-05-01T00:00:00Z", "1.0", false, "", AgentUpdateManifest.V2SchemaVersion, 41,
            "2026-05-08T00:00:00Z", new FileInfo(msi).Length, Pin);
        manifest = manifest with { Signature = Convert.ToBase64String(fixtureKey.SignData(
            Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(manifest)), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) };
        File.WriteAllText(storedManifest, JsonSerializer.Serialize(manifest));
        _metadata = new(Convert.ToBase64String(Encoding.UTF8.GetBytes(fixtureKey.ExportSubjectPublicKeyInfoPem())), "", "", "dev", Pin, false);
        _plan = new("msi", Version, "dev", msi, manifest.Sha256, Now.ToString("O"), "support fixture", AttemptId: Attempt,
            Sequence: manifest.Sequence, ArtifactLength: manifest.ArtifactLength, ManifestPath: storedManifest, SignerKeyIdentity: Pin,
            ManifestDigest: AgentUpdateManifestValidator.Digest(manifest));
        _watch = new(AgentUpdateWatchRecord.CurrentSchema, Attempt, Version, _plan.Sequence, _identity.ProductCode, OldVersion,
            OldVersion, Now, [], null, 0, 0, null, null, AgentUpdateWatchOutcomes.Passed, []);
    }

    [Theory]
    [InlineData("probe")]
    [InlineData("authenticode")]
    [InlineData("digest")]
    public void FailureBeforePublicationKeepsTheOldLkgAndFloor(string failure)
    {
        var plan = failure == "digest" ? _plan with { ManifestDigest = new string('b', 64) } : _plan;
        var promotion = Create(probe: (_, _) => failure != "probe", verify: (_, _) =>
        {
            if (failure == "authenticode") throw new InvalidOperationException("Fixture signer was denied.");
        });

        Assert.False(promotion.Apply(() => _journal, Change, _watch, plan, resume: false));
        Assert.Equal("old updater", File.ReadAllText(_store.HostPath));
        Assert.Equal("old MSI", File.ReadAllText(_store.MsiPath));
        Assert.Equal("old metadata", File.ReadAllText(_store.RecordPath));
        Assert.Equal(OldVersion, AgentUpdateRollbackFloor.Read(_store.UpdatesRoot)!.MinVersion);
        Assert.Equal(AgentUpdateStates.Installed, _journal.Phase);
        Assert.Equal(AgentUpdateWatchJournal.LkgPromotionFailed, _journal.FailureCode);
        Assert.Equal(Version, _journal.HealthyInstalledVersion);
        Assert.Null(_store.ReadPromotion());
        Assert.DoesNotContain(LkgProbe.PassedLogMarker, _logs);
    }

    [Fact]
    public void InterruptedRenamesRollForwardFromProbePassedBytes()
    {
        var probes = 0;
        var promotion = Create(probe: (path, version) =>
        {
            probes++;
            Assert.Contains("stage-" + Attempt, path);
            Assert.Equal("new updater", File.ReadAllText(path));
            return version == Version;
        }, validate: (path, root, missing) =>
        {
            AgentUpdateSecurity.ValidateTrustedPath(path, root, missing);
            if (Path.GetFileName(path) == $"retired-{Attempt}.exe") throw new IOException("Interrupted before host replacement.");
        });

        Assert.False(promotion.Apply(() => _journal, Change, _watch, _plan, resume: false));
        Assert.NotNull(_store.ReadPromotion());
        Assert.Equal(AgentUpdateWatchJournal.CommittedWatch, _journal.Phase);
        Assert.Equal("old updater", File.ReadAllText(_store.HostPath));
        Assert.Equal("new MSI", File.ReadAllText(_store.MsiPath));
        Assert.False(File.Exists(_store.RecordPath));
        Assert.Equal(OldVersion, AgentUpdateRollbackFloor.Read(_store.UpdatesRoot)!.MinVersion);

        var resumed = Create(probe: (_, _) => throw new InvalidOperationException("Verified staged bytes should resume without a new probe."));
        var wrongRuntime = Create(runtime: () => _identity with { ProductCode = Guid.NewGuid() });
        Assert.False(wrongRuntime.Apply(() => _journal, Change, _watch, _plan, resume: true));
        Assert.NotNull(_store.ReadPromotion());

        var stagedUpdater = Path.Combine(_store.Root, "stage-" + Attempt, AgentUpdateLkgStore.UpdaterFileName);
        File.WriteAllText(stagedUpdater, "changed stage bytes");
        Assert.False(resumed.Apply(() => _journal, Change, _watch, _plan, resume: true));
        Assert.Equal("old updater", File.ReadAllText(_store.HostPath));
        Assert.NotNull(_store.ReadPromotion());
        File.WriteAllText(stagedUpdater, "new updater");
        Assert.True(resumed.Apply(() => _journal, Change, _watch, _plan, resume: true));
        Assert.Equal(1, probes);
        Assert.Contains(LkgProbe.PassedLogMarker, _logs);
        Assert.Equal("new MSI", File.ReadAllText(_plan.ArtifactPath));
        Assert.Equal("new updater", File.ReadAllText(_store.HostPath));
        Assert.Equal("old updater", File.ReadAllText(Path.Combine(_store.Root, $"retired-{Attempt}.exe")));
        Assert.Equal(Version, _store.ReadHost()!.LkgVersion);
        Assert.Equal(Version, AgentUpdateRollbackFloor.Read(_store.UpdatesRoot)!.MinVersion);
        Assert.Equal(AgentUpdateStates.Installed, _journal.Phase);
        Assert.Equal(Version, _journal.HealthyInstalledVersion);
        Assert.Equal(_plan.Sequence, _journal.HealthyInstalledSequence);
        Assert.Null(_store.ReadPromotion());
    }

    [Fact]
    public void InterruptedUnpreparedCopiesAreRebuiltBeforeProbing()
    {
        var interrupted = Create(probe: (_, _) => throw new OperationCanceledException("Simulated process exit before the probe finished."));
        Assert.Throws<OperationCanceledException>(() => interrupted.Apply(() => _journal, Change, _watch, _plan, resume: false));
        var marker = Assert.IsType<AgentUpdateLkgPromotion>(_store.ReadPromotion());
        var stage = Path.Combine(_store.Root, marker.StageDir);
        Assert.False(File.Exists(Path.Combine(stage, "lkg.json")));
        File.WriteAllText(Path.Combine(stage, AgentUpdateSecurity.ArtifactFileName), "partial old stage file");
        Assert.Equal("old updater", File.ReadAllText(_store.HostPath));
        Assert.Equal("old MSI", File.ReadAllText(_store.MsiPath));

        var resumed = Create(probe: (path, _) =>
        {
            Assert.Equal("new MSI", File.ReadAllText(Path.Combine(Path.GetDirectoryName(path)!, AgentUpdateSecurity.ArtifactFileName)));
            return true;
        });
        Assert.True(resumed.Apply(() => _journal, Change, _watch, _plan, resume: true));
        Assert.Equal("new MSI", File.ReadAllText(_store.MsiPath));
        Assert.Null(_store.ReadPromotion());
    }

    [Fact]
    public void ClosedPromotionCanCleanUpAfterTheAttemptPlanDisappears()
    {
        var interruptedCleanup = Create(validate: (path, root, missing) =>
        {
            AgentUpdateSecurity.ValidateTrustedPath(path, root, missing);
            if (Path.GetFileName(path) == AgentUpdateLkgStore.PromotionFileName) throw new IOException("Interrupted cleanup.");
        });

        Assert.False(interruptedCleanup.Apply(() => _journal, Change, _watch, _plan, resume: false));
        Assert.Equal(AgentUpdateStates.Installed, _journal.Phase);
        Assert.NotNull(_store.ReadPromotion());
        Assert.True(Create().Apply(() => _journal, Change, null, null, resume: true));
        Assert.Null(_store.ReadPromotion());
        Assert.Equal(Version, _store.ReadHost()!.LkgVersion);
    }

    [Fact]
    public void ReleaseDoesNotAdmitAnUnsignedArtifactEvenWhenTheLabHookWouldAcceptIt()
    {
        var metadata = _metadata with { AllowedSignerKeyIdentity = "unsigned-dev", AllowUnsignedDevBuild = true };
        var asked = false;
        Assert.Throws<InvalidOperationException>(() => LkgPromotion.VerifyAuthenticode(metadata, _plan.ArtifactPath, _plan.Sha256, (_, _) =>
        {
            asked = true;
            return true;
        }));
        Assert.False(asked);
    }

    private LkgPromotion Create(Func<string, string, bool>? probe = null, Action<string, string>? verify = null,
        Action<string, string, bool>? validate = null, Func<LkgPromotion.RuntimeIdentity?>? runtime = null)
        => new(_store, _metadata, runtime ?? (() => _identity), validate ?? AgentUpdateSecurity.ValidateTrustedPath,
            (path, root) => AgentUpdateSecurity.ValidateTrustedPath(path, root, allowMissing: false),
            verify ?? ((_, _) => { }), probe ?? ((_, _) => true), _logs.Add);

    private AgentUpdateJournal Change(Func<AgentUpdateJournal, AgentUpdateJournal> patch) => _journal = patch(_journal);
    private static string Hash(string file) => Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(file)));
    public void Dispose() => _temp.Delete(recursive: true);
}
