using System.Security.Cryptography;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateRollbackFloorTests : IDisposable
{
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("rollback-floor-");
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-18T15:30:00Z");
    private static readonly string Hash = new('a', 64);

    [Fact]
    public void FloorOnlyRisesAndCorruptionFailsClosed()
    {
        var root = _root.FullName;
        Assert.Null(AgentUpdateRollbackFloor.Read(root));
        Assert.True(AgentUpdateRollbackFloor.Raise(root, "1.2.0", "watch_pass", 42, Hash, Now));
        var initial = AgentUpdateRollbackFloor.Read(root);
        Assert.False(AgentUpdateRollbackFloor.Raise(root, "1.1.0", "watch_pass", 43, Hash, Now));
        Assert.False(AgentUpdateRollbackFloor.Raise(root, "1.2.0-dev.1", "signed_manifest", 44, Hash, Now));
        Assert.Equal(initial, AgentUpdateRollbackFloor.Read(root));
        Assert.True(AgentUpdateRollbackFloor.Raise(root, "1.3.0", "watch_pass", 45, Hash, Now));
        Assert.Equal("1.3.0", AgentUpdateRollbackFloor.Read(root)!.MinVersion);
        var path = Path.Combine(root, AgentUpdateRollbackFloor.FileName);
        File.WriteAllText(path, "{incomplete");
        Assert.Throws<JsonException>(() => AgentUpdateRollbackFloor.Read(root));
        Assert.Throws<JsonException>(() => AgentUpdateRollbackFloor.Raise(root, "2.0.0", "watch_pass", 46, Hash, Now));
        Assert.Equal("{incomplete", File.ReadAllText(path));
    }

    [Fact]
    public void SignedFloorAppliesWithoutAWatchAndWithTheInstalledVersionBinding()
    {
        using var rsa = RSA.Create(2048);
        var signed = AgentUpdateManifestValidatorTests.SignedV2(rsa, "1.1.0");
        var payload = JsonSerializer.Serialize(signed);
        var keys = new[] { rsa.ExportSubjectPublicKeyInfoPem() };
        var root = _root.FullName;
        Assert.Throws<InvalidOperationException>(() => AgentUpdateRollbackFloor.ApplySignedManifest(root, "1.2.1", "1.2.0", payload, keys, Now));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateRollbackFloor.ApplySignedManifest(root, "1.2.1", "1.2.1", payload, keys, Now));
        Assert.Null(AgentUpdateRollbackFloor.Read(root));
        Assert.True(AgentUpdateRollbackFloor.ApplySignedManifest(root, "1.2.0", "1.2.0", payload, keys, Now));
        Assert.False(AgentUpdateRollbackFloor.ApplySignedManifest(root, "1.2.0", "1.2.0", payload, keys, Now.AddMinutes(1)));
        var floor = AgentUpdateRollbackFloor.Read(root)!;
        Assert.Equal("1.1.0", floor.MinVersion);
        Assert.Equal("signed_manifest", floor.Source);
        Assert.Equal(AgentUpdateManifestValidator.Digest(signed), floor.ManifestDigest);
        Assert.Equal(Now, floor.UpdatedUtc);
    }

    public void Dispose() => _root.Delete(recursive: true);
}
