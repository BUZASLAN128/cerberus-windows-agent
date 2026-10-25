using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Runs every case of tests/fixtures/agent-command-vectors.v1.json through the real envelope
/// processor, in file order on one agent with an empty replay store, and checks the golden
/// ack and result bytes. Unit/support tier.
/// </summary>
public sealed class CommandEnvelopeVectorsTests
{
    private static readonly string FixturePath = Path.Combine(AppContext.BaseDirectory, "fixtures", "agent-command-vectors.v1.json");
    private static readonly JsonElement Fixture = LoadFixture();

    private static JsonElement LoadFixture()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(FixturePath));
        return doc.RootElement.Clone();
    }

    private static CommandTrustAnchor FixtureAnchor()
    {
        var key = Fixture.GetProperty("test_key");
        return new CommandTrustAnchor(key.GetProperty("key_id").GetString()!,
            Convert.FromBase64String(key.GetProperty("spki_der_b64").GetString()!));
    }

    [Fact]
    public void Fixture_CarriesOnlyThePublicKeyAndItsKeyIdIsTheSpkiHash()
    {
        var raw = File.ReadAllText(FixturePath);
        Assert.DoesNotContain("PRIVATE KEY", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("private_key", raw, StringComparison.OrdinalIgnoreCase);
        var anchor = FixtureAnchor();
        Assert.Equal(AgentProfileMetadata.ComputeKeyId(anchor.Spki), anchor.KeyId);
        var file = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures",
            Fixture.GetProperty("test_key").GetProperty("trust_anchors_b64_file").GetString()!)).Trim();
        var parsed = Assert.Single(AgentProfileMetadata.ParseAnchors(file, Array.Empty<string>(), null));
        Assert.Equal(anchor.KeyId, parsed.KeyId);
    }

    [Fact]
    public Task EveryCase_GivesItsExpectedOutcomeWithAnInjectedAnchor()
        => RunAllCasesAsync(new[] { FixtureAnchor() });

#if CERBERUS_SERVER_PROFILE
    [Fact]
    public Task EveryCase_GivesItsExpectedOutcomeWithTheAnchorEmbeddedInTheBuild()
    {
        var embedded = AgentProfileMetadata.LoadCommandAnchors(Array.Empty<string>());
        Assert.Contains(embedded, a => a.KeyId == FixtureAnchor().KeyId);
        return RunAllCasesAsync(embedded);
    }
#endif

    [Fact]
    public void SampleAckAndResult_MatchTheEnvelopeBodyBuilders()
    {
        var ackSample = Fixture.GetProperty("sample_ack");
        var resultSample = Fixture.GetProperty("sample_result");
        var accept = Fixture.GetProperty("cases").EnumerateArray().First(c => c.GetProperty("name").GetString() == ackSample.GetProperty("for_case").GetString());
        var sha = accept.GetProperty("envelope_sha256").GetString()!;

        var ack = CommandEnvelope.BuildAckBody(sha, accepted: true, reason: null);
        Assert.Equal(ackSample.GetProperty("body").GetString(), System.Text.Encoding.UTF8.GetString(ack));
        Assert.Equal(ackSample.GetProperty("sha256").GetString(), CommandEnvelope.Sha256Hex(ack));

        using var body = JsonDocument.Parse(resultSample.GetProperty("body").GetString()!);
        var result = CommandEnvelope.BuildResultBody(
            body.RootElement.GetProperty("status").GetString()!, 0, null,
            body.RootElement.GetProperty("post_verify").Clone(), body.RootElement.GetProperty("envelope_sha256").GetString()!);
        Assert.Equal(resultSample.GetProperty("body").GetString(), System.Text.Encoding.UTF8.GetString(result));
        Assert.Equal(resultSample.GetProperty("sha256").GetString(), CommandEnvelope.Sha256Hex(result));
    }

    private static async Task RunAllCasesAsync(IReadOnlyList<CommandTrustAnchor> anchors)
    {
        await using var h = EnvelopeHarness.Create(o =>
        {
            o.AgentId = Fixture.GetProperty("agent_id").GetString()!;
            o.NowUnix = Fixture.GetProperty("now_unix").GetInt64();
            o.Anchors = anchors;
        });
        var accepted = 0;

        foreach (var vector in Fixture.GetProperty("cases").EnumerateArray())
        {
            var name = vector.GetProperty("name").GetString()!;
            var expected = vector.GetProperty("expected");
            var command = JsonSerializer.Deserialize<AgentCommand>(vector.GetProperty("pending_command").GetRawText())!;
            var acksBefore = h.Backend.Acks.Count;
            var code = expected.GetProperty("code").GetString();
            var rejectionsBefore = code is null ? 0 : h.Rejections(code);

            await h.Process(command);

            var ackSent = expected.GetProperty("ack_sent").GetBoolean();
            Assert.True(h.Backend.Acks.Count == acksBefore + (ackSent ? 1 : 0), $"{name}: ack count");
            if (ackSent)
            {
                var ack = h.Backend.Acks[^1];
                Assert.Equal(command.Id, ack.CommandId);
                Assert.Equal(expected.GetProperty("ack_decision").GetString(), ack.Json.GetProperty("decision").GetString());
                Assert.Equal(vector.GetProperty("envelope_sha256").GetString(), ack.Json.GetProperty("envelope_sha256").GetString());
                Assert.Equal(code, ack.Json.GetProperty("reason").GetString());
            }

            if (code is null)
            {
                accepted++;
                continue;
            }

            Assert.True(h.Rejections(code) == rejectionsBefore + 1, $"{name}: rejection counter for {code}");
        }

        await Wait.UntilAsync(() => h.Backend.Results.Count == accepted, "results of the accepted cases");
        Assert.All(h.Backend.Results, r => Assert.Equal("DONE", r.Json.GetProperty("status").GetString()));
        Assert.Equal(accepted, h.Ping.Calls + h.Facts.Calls + h.State.Calls);
    }
}
