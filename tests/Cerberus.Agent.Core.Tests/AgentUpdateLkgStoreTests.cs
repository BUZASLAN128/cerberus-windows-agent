using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateLkgStoreTests : IDisposable
{
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("lkg-support-");
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-18T15:30:00Z");
    private static readonly string Hash = new('a', 64);

    [Theory]
    [InlineData("none")]
    [InlineData("metadata")]
    [InlineData("version")]
    [InlineData("length")]
    [InlineData("hash")]
    [InlineData("digest")]
    [InlineData("sequence")]
    [InlineData("signer")]
    [InlineData("floor")]
    [InlineData("missing_floor")]
    [InlineData("replaced_version")]
    [InlineData("missing_replaced_version")]
    public void LkgRequiresAConsistentManifestPayloadFloorAndReplacedVersion(string failure)
    {
        using var rsa = RSA.Create(2048);
        var manifest = AgentUpdateManifestValidatorTests.SignedV2(rsa, null);
        var valid = Metadata(manifest);
        var record = failure switch
        {
            "metadata" => valid with { ProductCode = Guid.Empty },
            "version" => valid with { Version = "1.2.1" },
            "digest" => valid with { ManifestDigest = Hash },
            "sequence" => valid with { ManifestSequence = valid.ManifestSequence + 1 },
            "signer" => valid with { SignerKeyIdentity = "other" },
            _ => valid,
        };
        void Validate() => AgentUpdateLkgStore.ValidateRelease(record, manifest,
            failure == "missing_replaced_version" ? null : failure == "replaced_version" ? "1.3.0" : manifest.Version,
            failure == "missing_floor" ? null : Floor(failure == "floor" ? "1.3.0" : "1.0.0"),
            failure == "length" ? 99 : 100, failure == "hash" ? new string('b', 64) : Hash);
        if (failure == "none") Validate();
        else Assert.Throws<InvalidOperationException>(Validate);
    }

    [Fact]
    public void BootstrapCopiesThenPreservesValidHostAndRepairsMissingOrBadHost()
    {
        var store = CreateStore();
        var source = Path.Combine(_root.FullName, "installed-updater.exe");
        File.WriteAllText(source, "known installed updater bytes");
        var hash = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(source)));
        var sourceChecks = 0;
        bool Bootstrap(DateTimeOffset time) => store.BootstrapCore(source, "1.2.0", hash, time.ToOffset(TimeSpan.FromHours(3)),
            () => sourceChecks++, path => Assert.Equal("known installed updater bytes", File.ReadAllText(path)));

        Assert.True(Bootstrap(Now));
        var host = store.ReadHost()!;
        Assert.Equal("bootstrap", host.PlacedBy);
        Assert.Equal(Now, host.PlacedUtc);
        Assert.Equal(TimeSpan.Zero, host.PlacedUtc.Offset);
        Assert.False(Bootstrap(Now.AddMinutes(1)));
        Assert.Equal(Now, store.ReadHost()!.PlacedUtc);
        Assert.Equal(1, sourceChecks);
        File.Delete(store.HostPath);
        Assert.True(Bootstrap(Now.AddMinutes(1)));
        Assert.Equal("bootstrap_repair", store.ReadHost()!.PlacedBy);
        File.WriteAllText(store.HostPath, "invalid contents");
        Assert.True(Bootstrap(Now.AddMinutes(2)));
        Assert.Equal("bootstrap_repair", store.ReadHost()!.PlacedBy);
        Assert.Equal(hash, Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(store.HostPath))));
        Assert.Equal(3, sourceChecks);
    }

    [Fact]
    public void LkgRecordTimestampRoundTripsInUtc()
    {
        var store = CreateStore();
        using var rsa = RSA.Create(2048);
        var manifest = AgentUpdateManifestValidatorTests.SignedV2(rsa, null);
        var record = Metadata(manifest) with { PromotedUtc = Now.ToOffset(TimeSpan.FromHours(-5)) };
        AgentUpdateLkgStore.WriteRecord(store.RecordPath, store.UpdatesRoot, record);

        var saved = JsonSerializer.Deserialize<AgentUpdateLkgRecord>(File.ReadAllText(store.RecordPath), AgentUpdateLkgStore.RecordJson)!;
        Assert.Equal(record, saved);
        Assert.Equal(TimeSpan.Zero, saved.PromotedUtc.Offset);
        AgentUpdateLkgStore.ValidateRelease(saved, manifest, manifest.Version, Floor("1.0.0"), 100, Hash);
    }

    [Fact]
    public void PurgeBelowFloorRetainsTheHostAndItsMetadata()
    {
        var store = CreateStore();
        using var rsa = RSA.Create(2048);
        var manifest = AgentUpdateManifestValidatorTests.SignedV2(rsa, null);
        AgentUpdateLkgStore.WriteRecord(store.RecordPath, store.UpdatesRoot, Metadata(manifest));
        File.WriteAllText(store.ManifestPath, JsonSerializer.Serialize(manifest));
        File.WriteAllBytes(store.MsiPath, new byte[100]);
        File.WriteAllText(store.HostPath, "host");
        File.WriteAllText(store.HostRecordPath, "host record");
        Assert.False(store.PurgeBelowFloor(Floor("1.2.0")));
        Assert.True(store.PurgeBelowFloor(Floor("1.2.1")));
        Assert.False(File.Exists(store.MsiPath));
        Assert.False(File.Exists(store.ManifestPath));
        Assert.False(File.Exists(store.RecordPath));
        Assert.Equal("host", File.ReadAllText(store.HostPath));
        Assert.Equal("host record", File.ReadAllText(store.HostRecordPath));
    }

    [Fact]
    public void PromotionReceiptCanResumeOnlyFromItsOwnStage()
    {
        var store = CreateStore();
        Assert.Null(store.ReadPromotion());
        var promotion = new AgentUpdateLkgPromotion("attempt1", "1.2.1", Hash, Hash, Hash, Hash, "stage-attempt1");
        store.WritePromotion(promotion);
        Assert.Equal(promotion, store.ReadPromotion());
        Assert.Throws<InvalidOperationException>(() => store.WritePromotion(promotion with { StageDir = "stage-other" }));
        Assert.Equal(promotion, store.ReadPromotion());
    }

    [Fact]
    public void LkgDescriptorAcceptsTheProtectedRootAndRejectsTheProductRootPermissions()
    {
        Assert.True(OperatingSystem.IsWindows());
        var sddl = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";
        AgentUpdateSecurity.ValidateDescriptor(new RawSecurityDescriptor(sddl), isProductRoot: false);
        Assert.Throws<InvalidOperationException>(() => AgentUpdateSecurity.ValidateDescriptor(
            new RawSecurityDescriptor(AgentUpdateSecurity.ProductDirectorySddl), isProductRoot: false));
    }

    private AgentUpdateLkgStore CreateStore()
    {
        var store = new AgentUpdateLkgStore(_root.FullName);
        Directory.CreateDirectory(store.Root);
        return store;
    }

    private static AgentUpdateLkgRecord Metadata(AgentUpdateManifest manifest) => new(AgentUpdateLkgStore.Schema, manifest.Version,
        Guid.NewGuid(), Hash, 100, AgentUpdateManifestValidator.Digest(manifest), manifest.Sequence, manifest.EffectiveSignerKeyIdentity!,
        Hash, Hash, "attempt1", Now);

    private static AgentUpdateRollbackFloorRecord Floor(string version)
        => new(AgentUpdateRollbackFloor.Schema, version, "watch_pass", 44, Hash, Now);
    public void Dispose() => _root.Delete(recursive: true);
}
