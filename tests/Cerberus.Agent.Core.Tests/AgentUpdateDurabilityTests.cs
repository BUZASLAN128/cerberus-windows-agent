using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateDurabilityTests
{
    [Fact]
    public void PublisherIdentity_BindsSpkiNotCertificateSerialOrRenewal()
    {
        using var key = RSA.Create(2048);
        var firstRequest = new CertificateRequest("CN=Publisher A", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var secondRequest = new CertificateRequest("CN=Renewed Publisher", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var first = firstRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var second = secondRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        Assert.NotEqual(first.Thumbprint, second.Thumbprint);
        Assert.Equal(AgentUpdateAuthenticode.PublisherSpkiSha256(first), AgentUpdateAuthenticode.PublisherSpkiSha256(second));
        Assert.StartsWith("sha256:", AgentUpdateAuthenticode.PublisherSpkiSha256(first));
    }

    [Theory]
    [InlineData("https://releases.example/package/a.msi", true)]
    [InlineData("https://releases.example/package-evil/a.msi", false)]
    [InlineData("https://releases.example.evil/package/a.msi", false)]
    [InlineData("http://releases.example/package/a.msi", false)]
    [InlineData("https://user@releases.example/package/a.msi", false)]
    public void ArtifactPrefix_BindsOriginAndPathSegment(string value, bool allowed)
        => Assert.Equal(allowed, AgentUpdateManifestValidator.IsAllowedArtifactUri(new Uri(value), "https://releases.example/package"));

    [Theory]
    [InlineData(0, AgentUpdateStates.HealthPending)]
    [InlineData(3010, AgentUpdateStates.PendingReboot)]
    [InlineData(1618, AgentUpdateStates.RetryableBusy)]
    [InlineData(1603, AgentUpdateStates.Failed)]
    public void InstallerExitCode_IsNotHealthyInstalledEvidence(int exit, string expected)
        => Assert.Equal(expected, AgentUpdateInstallerResult.FromMsiExitCode(exit, null, null).State);

    [Fact]
    public void CrashAfterInstallerFence_IsUnfinishedAndNeverASecondLaunchPermission()
    {
        foreach (var phase in new[] { "install_may_have_started", AgentUpdateStates.Installing, AgentUpdateStates.RecoveryRequired, AgentUpdateStates.PendingReboot })
        {
            var journal = new AgentUpdateJournal { AttemptId = "attempt1", Phase = phase };
            Assert.True(journal.MayHaveStartedInstallation);
            Assert.True(journal.HasUnfinishedAttempt);
            Assert.False(AgentUpdateStates.CanApply(phase));
        }
        Assert.False(new AgentUpdateJournal { AttemptId = "attempt1", Phase = AgentUpdateStates.Blocked }.HasUnfinishedAttempt);
    }

    [Fact]
    public void DurableJournal_RejectsUnknownPhaseAndPreservesRecord()
    {
        var root = NewRoot();
        var path = Path.Combine(root, "transaction.json");
        AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { Phase = "unrecognized" });
        var before = File.ReadAllBytes(path);
        Assert.Throws<InvalidOperationException>(() => new AgentUpdateJournalStore(root).Read());
        Assert.Equal(before, File.ReadAllBytes(path));
    }

    [Fact]
    public void AcceptedSequence_RequiresExactHighestDigestAndRejectsCorruption()
    {
        var root = NewRoot();
        var path = Path.Combine(root, "highest-sequence.json");
        var digest = new string('a', 64);
        AgentUpdateDurableFile.Write(path, root, new { schema_version = "agent.update.sequence.v2", highest_sequence = 42, manifest_digest = digest });
        AgentUpdateSequenceStore.RequireAccepted(root, 42, digest);
        Assert.Throws<InvalidOperationException>(() => AgentUpdateSequenceStore.RequireAccepted(root, 41, digest));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateSequenceStore.RequireAccepted(root, 42, new string('b', 64)));
        File.WriteAllText(path, "{");
        Assert.Throws<InvalidOperationException>(() => AgentUpdateSequenceStore.ReadHighest(root));
    }

    [Fact]
    public async Task ReportSequence_PersistsAcrossAttemptsAndReusesUnchangedPayload()
    {
        var root = NewRoot();
        var store = new AgentUpdateStateStore(Path.Combine(root, "state.json"), Path.Combine(root, "result.json"));
        var state = AgentUpdateState.NotChecked("1.0.0") with { State = AgentUpdateStates.Staged, AttemptId = "one" };
        await store.WriteAsync(state, CancellationToken.None);
        var first = await store.ReadAsync("1.0.0", CancellationToken.None);
        await store.WriteAsync(first, CancellationToken.None);
        var retry = await store.ReadAsync("1.0.0", CancellationToken.None);
        Assert.Equal(first.ReportSequence, retry.ReportSequence);
        await store.WriteAsync(first with { AttemptId = "two" }, CancellationToken.None);
        var next = await new AgentUpdateStateStore(store.StatePath, store.InstallerResultPath).ReadAsync("1.0.0", CancellationToken.None);
        Assert.Equal(first.ReportSequence + 1, next.ReportSequence);
        Assert.Equal("agent.update.status.v2", next.ToHeartbeatStatus()["schema_version"]);
        Assert.Equal(next.ToHeartbeatStatus(), next.ToCommandResultPayload());
    }

    [Fact]
    public void BootIdentity_IsStableAcrossReadsWithinOneBoot()
    {
        if (!OperatingSystem.IsWindows()) return;
        var first = AgentUpdateBootIdentity.Read();
        Assert.True(Guid.TryParse(first, out _));
        Assert.Equal(first, AgentUpdateBootIdentity.Read());
    }

    [Fact]
    public void V2Manifest_RejectsSignedMissingLengthExpiredAndDuplicateFields()
    {
        using var rsa = RSA.Create(2048);
        var unsigned = new AgentUpdateManifest("msi", "2.0.0", "stable", "https://releases.example/package/a.msi", new string('a', 64),
            "Publisher", DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"), "agent.heartbeat.v1", false, "",
            AgentUpdateManifest.V2SchemaVersion, 42, DateTimeOffset.UtcNow.AddDays(1).ToString("O"), 100, "sha256:" + new string('b', 64));
        AgentUpdateManifest Sign(AgentUpdateManifest input) => input with { Signature = Convert.ToBase64String(rsa.SignData(Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(input)), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) };
        AgentUpdateManifest Validate(AgentUpdateManifest input) => AgentUpdateManifestValidator.Validate(input, rsa.ExportSubjectPublicKeyInfoPem(), "stable", new[] { "https://releases.example/package/" }, "1.0.0");
        var valid = Sign(unsigned);
        Assert.Equal(valid, Validate(valid));
        Assert.Throws<InvalidOperationException>(() => Validate(Sign(unsigned with { ArtifactLength = null })));
        Assert.Throws<InvalidOperationException>(() => Validate(Sign(unsigned with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(-1).ToString("O") })));
        var json = JsonSerializer.Serialize(valid);
        json = json.Insert(1, "\"sequence\":42,");
        Assert.Throws<InvalidOperationException>(() => AgentUpdateManifestValidator.ParseAndValidateJson(json, rsa.ExportSubjectPublicKeyInfoPem(), "stable", new[] { "https://releases.example/package/" }, "1.0.0"));
    }

    [Fact]
    public void VolumeRootBoundary_AcceptsDescendantWithoutAcceptingSibling()
    {
        var path = Path.GetFullPath(Path.GetTempPath());
        Assert.True(AgentUpdateSecurity.IsUnderDirectory(path, Path.GetPathRoot(path)!));
        Assert.False(AgentUpdateSecurity.IsUnderDirectory(Path.Combine(path, "protected-evil", "a"), Path.Combine(path, "protected")));
    }

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-durability-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
