using System.Security.Cryptography;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateCeilingTests
{
    private static readonly string[] Prefixes = { "https://releases.cerberus.local/" };

    [Fact]
    public void MaxV2ValidityWindow_IsFortyFiveDaysAndCoversReleaseToolingAndPublishedWindow()
    {
        Assert.Equal(TimeSpan.FromDays(45), AgentUpdateManifestValidator.MaxV2ValidityWindow);
        // build-agent-public-release.ps1 writes AddDays(30); published dev manifests 0.2.144/0.2.145 span the same 30 days.
        var published = DateTimeOffset.Parse("2026-10-08T21:36:10Z") - DateTimeOffset.Parse("2026-09-08T21:36:10Z");
        Assert.Equal(TimeSpan.FromDays(30), published);
        Assert.True(published < AgentUpdateManifestValidator.MaxV2ValidityWindow);
    }

    [Theory]
    [InlineData(30, 0, true)]
    [InlineData(45, 0, true)]
    [InlineData(45, 1, false)]
    [InlineData(46, 0, false)]
    public void ValidateV2_EnforcesValidityWindowAtTheBoundary(int days, int extraTicks, bool accepted)
    {
        using var rsa = RSA.Create(2048);
        var released = DateTimeOffset.UtcNow.AddHours(-1);
        var window = TimeSpan.FromDays(days) + TimeSpan.FromTicks(extraTicks);
        var manifest = SignedV2(rsa, released, released + window);

        if (accepted)
        {
            Assert.Equal("1.2.0", AgentUpdateManifestValidator.Validate(manifest, PublicKeyPem(rsa), "stable", Prefixes).Version);
            return;
        }

        var ex = Assert.Throws<InvalidOperationException>(() =>
            AgentUpdateManifestValidator.Validate(manifest, PublicKeyPem(rsa), "stable", Prefixes));
        Assert.Contains("validity window is too long", ex.Message);
    }

    [Fact]
    public void ValidateV1_HasNoValidityWindow()
    {
        using var rsa = RSA.Create(2048);
        var unsigned = new AgentUpdateManifest(
            "msi", "1.2.0", "stable", "https://releases.cerberus.local/agent/1.2.0.msi", new string('a', 64),
            "Cerberus Agent Release", "2020-01-01T00:00:00Z", "agent.heartbeat.v1", false, "");
        var signed = unsigned with { Signature = Sign(rsa, unsigned) };

        Assert.Equal("1.2.0", AgentUpdateManifestValidator.Validate(signed, PublicKeyPem(rsa), "stable", Prefixes).Version);
    }

    [Theory]
    [InlineData(0L, true)]
    [InlineData(1L, true)]
    [InlineData(AgentUpdateSequenceStore.MaxSequenceLeadMilliseconds, true)]
    [InlineData(AgentUpdateSequenceStore.MaxSequenceLeadMilliseconds + 1, false)]
    [InlineData(long.MaxValue, false)]
    public void AcceptSequence_EnforcesAbsoluteCeilingAgainstTheSuppliedClock(long leadMilliseconds, bool accepted)
    {
        var now = DateTimeOffset.Parse("2026-10-25T12:00:00Z");
        var sequence = now.ToUnixTimeMilliseconds() + leadMilliseconds;
        if (leadMilliseconds == long.MaxValue)
            sequence = long.MaxValue;
        var root = NewRoot();
        var digest = new string('a', 64);

        if (accepted)
        {
            AssertCeilingDoesNotReject(root, sequence, digest, now);
            return;
        }

        var ex = Assert.Throws<InvalidOperationException>(() => AgentUpdateSequenceStore.Accept(root, sequence, digest, now));
        Assert.Contains("out of range", ex.Message);
        Assert.Equal(0, AgentUpdateSequenceStore.ReadHighest(root));
    }

    [Fact]
    public void AcceptSequence_CeilingAllowsPublishedAndPastValues()
    {
        var now = DateTimeOffset.Parse("2026-10-25T12:00:00Z");
        var digest = new string('a', 64);
        const long published = 1788903185152L; // Unix ms of the 2026-09-08 dev release

        AssertCeilingDoesNotReject(NewRoot(), published, digest, now);
        AssertCeilingDoesNotReject(NewRoot(), now.ToUnixTimeMilliseconds(), digest, now);
        AssertCeilingDoesNotReject(NewRoot(), 42, digest, now);
    }

    // Persisting needs a protected root (owner/ACL provenance), which a non-elevated run cannot create.
    // The ceiling check runs first, so an in-range value must never fail with the ceiling error.
    private static void AssertCeilingDoesNotReject(string root, long sequence, string digest, DateTimeOffset now)
    {
        try
        {
            AgentUpdateSequenceStore.Accept(root, sequence, digest, now);
            Assert.Equal(sequence, AgentUpdateSequenceStore.ReadHighest(root));
        }
        catch (InvalidOperationException ex)
        {
            Assert.DoesNotContain("out of range", ex.Message);
        }
    }

    private static AgentUpdateManifest SignedV2(RSA rsa, DateTimeOffset released, DateTimeOffset expires)
    {
        var unsigned = new AgentUpdateManifest(
            "msi", "1.2.0", "stable", "https://releases.cerberus.local/agent/1.2.0.msi", new string('a', 64),
            "Cerberus Agent Release", released.ToString("O"), "agent.heartbeat.v1", false, "",
            AgentUpdateManifest.V2SchemaVersion, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), expires.ToString("O"),
            1234, "sha256:" + new string('c', 64));
        return unsigned with { Signature = Sign(rsa, unsigned) };
    }

    private static string Sign(RSA rsa, AgentUpdateManifest unsigned)
        => Convert.ToBase64String(rsa.SignData(
            Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(unsigned)),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));

    private static string PublicKeyPem(RSA rsa)
        => "-----BEGIN PUBLIC KEY-----\n" +
           Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo(), Base64FormattingOptions.InsertLineBreaks) +
           "\n-----END PUBLIC KEY-----\n";

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-ceiling-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
