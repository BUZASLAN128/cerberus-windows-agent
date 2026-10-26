using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentTimingPolicyTests
{
    private static readonly AgentTimingBounds Desktop = new(1, 3600, 60, 86400, 60);
    private static readonly AgentTimingBounds Server = new(30, 300, 300, 3600, 3600);

#if CERBERUS_SERVER_PROFILE
    private static readonly AgentTimingBounds Expected = Server;
#else
    private static readonly AgentTimingBounds Expected = Desktop;
#endif

    [Fact]
    public void CurrentBounds_MatchCompiledProfileDefaults()
    {
        Assert.Equal(Expected, AgentProfileMetadata.Timing);
        Assert.Equal(Expected, AgentTimingPolicy.Current.Bounds);
    }

    [Fact]
    public void CurrentBounds_IgnoreEnvironmentVariablesNamedLikeTheMetadata()
    {
        var names = new[]
        {
            "AgentPollFloorSeconds", "AgentPollCeilingSeconds", "AgentSnapshotFloorSeconds",
            "AgentSnapshotCeilingSeconds", "AgentSnapshotDefaultSeconds",
            "AGENT_POLL_FLOOR_SECONDS", "AGENT_POLL_CEILING_SECONDS", "AGENT_SNAPSHOT_INTERVAL_SECONDS",
        };
        var saved = names.ToDictionary(n => n, Environment.GetEnvironmentVariable);
        try
        {
            foreach (var name in names)
                Environment.SetEnvironmentVariable(name, "1");

            Assert.Equal(Expected, AgentProfileMetadata.Timing);
            Assert.Equal(Expected, new AgentTimingPolicy(AgentProfileMetadata.Timing).Bounds);
        }
        finally
        {
            foreach (var (name, value) in saved)
                Environment.SetEnvironmentVariable(name, value);
        }
    }

    [Theory]
    [InlineData("AgentTimingPolicy.cs")]
    [InlineData("AgentProfileMetadata.cs")]
    public void TimingSources_ReadNoEnvironmentRegistryOrFiles(string fileName)
    {
        var path = FindCoreSource(fileName);
        var source = File.ReadAllText(path);
        var forbidden = new Regex(
            @"\bEnvironment\.|Registry|\bFile\.|\bDirectory\.|FileStream|StreamReader|\bFileInfo\b|\bDirectoryInfo\b|ConfigurationManager",
            RegexOptions.CultureInvariant);

        Assert.DoesNotMatch(forbidden, source);
    }

    [Theory]
    [InlineData(1, 0, 1)]
    [InlineData(70, 0, 70)]
    [InlineData(100000, 0, 3600)]
    [InlineData(40, 60, 60)]
    [InlineData(5000, 60, 3600)]
    public void PollDelay_Desktop_ClampsToFloorAndCeiling_ThenAppliesCallerMinimum(int jittered, int minimum, int expected)
        => Assert.Equal(expected, new AgentTimingPolicy(Desktop).PollDelaySeconds(jittered, minimum));

    [Theory]
    [InlineData(1, 0, 30)]
    [InlineData(29, 0, 30)]
    [InlineData(30, 0, 30)]
    [InlineData(120, 0, 120)]
    [InlineData(300, 0, 300)]
    [InlineData(301, 0, 300)]
    [InlineData(100000, 0, 300)]
    [InlineData(10, 60, 60)]
    [InlineData(10, 300, 300)]
    public void PollDelay_Server_ClampsToFloorAndCeiling_ThenAppliesCallerMinimum(int jittered, int minimum, int expected)
        => Assert.Equal(expected, new AgentTimingPolicy(Server).PollDelaySeconds(jittered, minimum));

    [Theory]
    [InlineData(0, 3600)]
    [InlineData(1, 300)]
    [InlineData(299, 300)]
    [InlineData(300, 300)]
    [InlineData(1800, 1800)]
    [InlineData(3600, 3600)]
    [InlineData(3601, 3600)]
    [InlineData(int.MaxValue, 3600)]
    public void SnapshotDelay_Server_ZeroMeansDefault_OtherValuesClamp(int fromServer, int expected)
        => Assert.Equal(expected, new AgentTimingPolicy(Server).SnapshotDelaySeconds(fromServer));

    [Theory]
    [InlineData(0, 60)]
    [InlineData(1, 60)]
    [InlineData(60, 60)]
    [InlineData(300, 300)]
    [InlineData(86400, 86400)]
    [InlineData(86401, 86400)]
    public void SnapshotDelay_Desktop_ZeroMeansDefault_OtherValuesClamp(int fromServer, int expected)
        => Assert.Equal(expected, new AgentTimingPolicy(Desktop).SnapshotDelaySeconds(fromServer));

    [Theory]
    [InlineData(1800, 1440, 2160)]
    [InlineData(300, 300, 360)]
    [InlineData(3600, 2880, 3600)]
    [InlineData(0, 2880, 3600)]
    [InlineData(-5, 300, 360)]
    [InlineData(int.MaxValue, 2880, 3600)]
    public void SnapshotDelayWithJitter_Server_StaysWithinJitterAndClamps(int fromServer, int min, int max)
    {
        var policy = new AgentTimingPolicy(Server);
        for (var i = 0; i < 200; i++)
        {
            var delay = HeartbeatLoop.SnapshotDelayWithJitter(policy, fromServer);
            Assert.InRange(delay, min, max);
        }
    }

    [Fact]
    public void ParseTiming_AcceptsConsistentValues()
        => Assert.Equal(Server, AgentProfileMetadata.ParseTiming(Metadata(Server)));

    [Theory]
    [InlineData("AgentPollFloorSeconds", "abc")]
    [InlineData("AgentPollFloorSeconds", "")]
    [InlineData("AgentPollFloorSeconds", "-5")]
    [InlineData("AgentPollFloorSeconds", "1.5")]
    [InlineData("AgentPollFloorSeconds", "0")]
    [InlineData("AgentSnapshotFloorSeconds", "0")]
    [InlineData("AgentPollFloorSeconds", "301")]
    [InlineData("AgentSnapshotFloorSeconds", "3601")]
    [InlineData("AgentSnapshotDefaultSeconds", "299")]
    [InlineData("AgentSnapshotDefaultSeconds", "3601")]
    [InlineData("AgentPollCeilingSeconds", "29")]
    public void ParseTiming_RejectsInvalidOrInconsistentValues(string key, string value)
    {
        var values = ToDictionary(Server);
        values[key] = value;

        Assert.Throws<InvalidOperationException>(
            () => AgentProfileMetadata.ParseTiming(k => values.GetValueOrDefault(k)));
    }

    [Fact]
    public void ParseTiming_RejectsMissingKey()
    {
        var values = ToDictionary(Server);
        values.Remove("AgentPollCeilingSeconds");

        Assert.Throws<InvalidOperationException>(
            () => AgentProfileMetadata.ParseTiming(k => values.GetValueOrDefault(k)));
    }

    [Fact]
    public void ParseAnchors_ReturnsKeyIdsAsFirst16HexOfSpkiSha256_AndSkipsBadLines()
    {
        var good1 = NewSpki(2048);
        var good2 = NewSpki(3072);
        var weak = NewSpki(1024);
        var value = Encode(
            Convert.ToBase64String(good1),
            "",
            "not-base64!!",
            Convert.ToBase64String(weak),
            Convert.ToBase64String(good1),
            Convert.ToBase64String(good2));
        var log = new CapturingLogger();

        var anchors = AgentProfileMetadata.ParseAnchors(value, null, log);

        Assert.Equal(2, anchors.Count);
        Assert.Equal(ExpectedKeyId(good1), anchors[0].KeyId);
        Assert.Equal(ExpectedKeyId(good2), anchors[1].KeyId);
        Assert.Equal(good1, anchors[0].Spki);
        Assert.Matches("^[0-9a-f]{16}$", anchors[0].KeyId);
        Assert.Equal(2, log.Warnings.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("%%%not base64")]
    public void ParseAnchors_EmptyOrInvalidValue_YieldsNoAnchors(string? value)
        => Assert.Empty(AgentProfileMetadata.ParseAnchors(value, null, new CapturingLogger()));

    [Fact]
    public void ParseAnchors_DropsAnchorEqualToManifestKey_AndLogsItsKeyIdOnce()
    {
        using var manifestRsa = RSA.Create(2048);
        var manifestSpki = manifestRsa.ExportSubjectPublicKeyInfo();
        var other = NewSpki(2048);
        var value = Encode(Convert.ToBase64String(manifestSpki), Convert.ToBase64String(other));
        var log = new CapturingLogger();

        var anchors = AgentProfileMetadata.ParseAnchors(value, new[] { manifestRsa.ExportSubjectPublicKeyInfoPem() }, log);

        var kept = Assert.Single(anchors);
        Assert.Equal(ExpectedKeyId(other), kept.KeyId);
        var warning = Assert.Single(log.Warnings);
        Assert.Contains(ExpectedKeyId(manifestSpki), warning);
    }

    [Fact]
    public void ParseAnchors_OnlyAnchorEqualToManifestKey_YieldsNone()
    {
        using var manifestRsa = RSA.Create(2048);
        var value = Encode(Convert.ToBase64String(manifestRsa.ExportSubjectPublicKeyInfo()));

        var anchors = AgentProfileMetadata.ParseAnchors(
            value, new[] { manifestRsa.ExportRSAPublicKeyPem() }, new CapturingLogger());

        Assert.Empty(anchors);
    }

    [Fact]
    public void ParseAnchors_KeepsAnchorWhenManifestKeyDiffers_AndIgnoresUnparsableManifestPem()
    {
        var anchor = NewSpki(2048);
        using var manifestRsa = RSA.Create(2048);
        var log = new CapturingLogger();

        var anchors = AgentProfileMetadata.ParseAnchors(
            Encode(Convert.ToBase64String(anchor)),
            new[] { manifestRsa.ExportSubjectPublicKeyInfoPem(), "not a pem" },
            log);

        Assert.Equal(ExpectedKeyId(anchor), Assert.Single(anchors).KeyId);
        Assert.Empty(log.Warnings);
    }

    private static string Encode(params string[] lines)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("\n", lines)));

    private static byte[] NewSpki(int bits)
    {
        using var rsa = RSA.Create(bits);
        return rsa.ExportSubjectPublicKeyInfo();
    }

    private static string ExpectedKeyId(byte[] spki)
        => Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant()[..16];

    private static Dictionary<string, string> ToDictionary(AgentTimingBounds b) => new()
    {
        ["AgentPollFloorSeconds"] = b.PollFloor.ToString(),
        ["AgentPollCeilingSeconds"] = b.PollCeiling.ToString(),
        ["AgentSnapshotFloorSeconds"] = b.SnapshotFloor.ToString(),
        ["AgentSnapshotCeilingSeconds"] = b.SnapshotCeiling.ToString(),
        ["AgentSnapshotDefaultSeconds"] = b.SnapshotDefault.ToString(),
    };

    private static Func<string, string?> Metadata(AgentTimingBounds b)
    {
        var values = ToDictionary(b);
        return k => values.GetValueOrDefault(k);
    }

    private static string FindCoreSource(string fileName)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "src", "Cerberus.Agent.Core", fileName);
            if (File.Exists(candidate))
                return candidate;
            dir = dir.Parent;
        }

        throw new FileNotFoundException($"Core source not found: {fileName}");
    }

    private sealed class CapturingLogger : IAgentLogger
    {
        public List<string> Warnings { get; } = new();

        public void Info(string message) { }

        public void Warn(string message) => Warnings.Add(message);

        public void Error(string message, Exception? ex = null) { }
    }
}
