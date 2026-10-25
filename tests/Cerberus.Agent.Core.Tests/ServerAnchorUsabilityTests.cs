using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.Core.Tests;

// A server build must ship with at least one command trust anchor the runtime parser keeps.
// Support tier for the release-script cases (pwsh runs only the validation in Get-ReleaseProfileBuild; no build, no MSI).
public sealed class ServerAnchorUsabilityTests
{
#if CERBERUS_SERVER_PROFILE
    [Fact]
    public void CompiledAnchors_ParseToAtLeastOneUsableAnchor()
    {
        var anchors = AgentProfileMetadata.LoadCommandAnchors(Array.Empty<string>());

        Assert.NotEmpty(anchors);
        Assert.All(anchors, a =>
        {
            Assert.Matches("^[0-9a-f]{16}$", a.KeyId);
            Assert.Equal(AgentProfileMetadata.ComputeKeyId(a.Spki), a.KeyId);
        });
    }
#endif

    [Fact]
    public void ReleaseValidation_AcceptsTheFixtureAnchor_AndPrintsItsKeyId()
    {
        var result = Validate(FixtureValue());

        Assert.Equal(0, result.ExitCode);
        var keyId = AgentProfileMetadata.ComputeKeyId(FixtureSpkiLines().Single());
        Assert.Contains("Command trust anchors: " + keyId, result.Output);
    }

    [Fact]
    public void ReleaseValidation_AcceptsAFixtureLineBesideAnotherStrongKey()
    {
        using var other = RSA.Create(2048);
        var value = Encode(FixtureSpkiLines().Select(Convert.ToBase64String).Append(Convert.ToBase64String(other.ExportSubjectPublicKeyInfo())));

        var result = Validate(value);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains(AgentProfileMetadata.ComputeKeyId(other.ExportSubjectPublicKeyInfo()), result.Output);
    }

    [Fact]
    public void ReleaseValidation_RejectsTruncatedNonRsaWeakAndJunkLines_NamingTheLine()
    {
        var good = Convert.ToBase64String(FixtureSpkiLines().Single());
        using var weak = RSA.Create(1024);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var cases = new Dictionary<string, string>
        {
            ["truncated"] = good[..(good.Length - 12)],
            ["non-rsa"] = Convert.ToBase64String(ec.ExportSubjectPublicKeyInfo()),
            ["rsa-1024"] = Convert.ToBase64String(weak.ExportSubjectPublicKeyInfo()),
            ["junk"] = "not-a-key!!",
        };

        foreach (var (name, bad) in cases)
        {
            var alone = Validate(Encode(new[] { bad }));
            Assert.True(alone.ExitCode != 0, name + " alone must fail.");
            Assert.Contains("line 1 is not a usable RSA public key", alone.Output);

            var withGood = Validate(Encode(new[] { good, bad }));
            Assert.True(withGood.ExitCode != 0, name + " beside a good line must still fail the build.");
            Assert.Contains("line 2 is not a usable RSA public key", withGood.Output);
        }
    }

    [Fact]
    public void ReleaseValidation_RejectsEmptyAndNonBase64Values()
    {
        var blank = Validate(Convert.ToBase64String(Encoding.UTF8.GetBytes("\n \n")));
        Assert.NotEqual(0, blank.ExitCode);
        Assert.Contains("no usable key", blank.Output);

        var notBase64 = Validate("QUJD!");
        Assert.NotEqual(0, notBase64.ExitCode);
    }

    private static string FixtureValue()
        => File.ReadAllText(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "tests", "fixtures", "agent-command-test-anchors.b64")).Trim();

    private static IEnumerable<byte[]> FixtureSpkiLines()
        => Encoding.UTF8.GetString(Convert.FromBase64String(FixtureValue()))
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(Convert.FromBase64String);

    private static string Encode(IEnumerable<byte[]> spkis) => Encode(spkis.Select(Convert.ToBase64String));

    private static string Encode(IEnumerable<string> lines)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("\n", lines)));

    private static (int ExitCode, string Output) Validate(string anchorsB64)
    {
        var file = Path.Combine(Path.GetTempPath(), $"anchors-{Guid.NewGuid():N}.b64");
        File.WriteAllText(file, anchorsB64);
        try
        {
            return ServerPackageStaticTests.RunProfileLib($"'server' '{file}' @{{}} '' ''");
        }
        finally
        {
            File.Delete(file);
        }
    }
}
