using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Undecodable text in the unsigned outer envelope (lone surrogate escapes) is a
/// <c>envelope_malformed</c> rejection, not an exception. Unit/support tier.
/// </summary>
public sealed class CommandEnvelopeWireTests
{
    private const string LoneSurrogate = "\\ud800"; // six characters: backslash, u, d, 8, 0, 0

    private static async Task<(string Entry, string Envelope)> ValidEntryAsync()
    {
        await using var h = EnvelopeHarness.Create();
        var cmd = h.Cmd();
        return (JsonSerializer.Serialize(cmd), cmd.Envelope!.Value.GetRawText());
    }

    private static JsonElement Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    [Fact]
    public async Task PositiveControl_ValidOuterEnvelopeParses()
    {
        var (_, envelope) = await ValidEntryAsync();

        Assert.True(CommandEnvelope.TryReadWire(Parse(envelope), out var wire, out var code));
        Assert.NotNull(wire);
        Assert.Null(code);
    }

    // A lone-surrogate name that leads the object does not make TryGetProperty throw; the theory below covers names that do.
    [Fact]
    public async Task LoneSurrogatePropertyName_DoesNotThrowAndIsIgnored()
    {
        var (_, envelope) = await ValidEntryAsync();
        var bad = "{\"" + LoneSurrogate + "\":1," + envelope[1..];

        var ok = CommandEnvelope.TryReadWire(Parse(bad), out var wire, out var code);

        Assert.True(ok);
        Assert.NotNull(wire);
        Assert.Null(code);
    }

    // Empirical on .NET 10: a name that is a truncated prefix of a known key, followed by a lone surrogate
    // escape and placed after the known keys, makes TryGetProperty throw. Names extending a full key
    // (alg, signature, delegation, ...) or leading the object parse without throwing.
    [Theory]
    [InlineData("a")]
    [InlineData("al")]
    [InlineData("deleg")]
    [InlineData("key_")]
    [InlineData("sign")]
    [InlineData("signed_by")]
    public async Task LoneSurrogateTruncatedKeyNameAfterKnownKeys_IsMalformedWithoutThrowing(string prefix)
    {
        var (_, envelope) = await ValidEntryAsync();
        var bad = envelope[..^1] + ",\"" + prefix + LoneSurrogate + "\":1}";

        var ok = CommandEnvelope.TryReadWire(Parse(bad), out var wire, out var code);

        Assert.False(ok);
        Assert.Null(wire);
        Assert.Equal(EnvelopeCodes.Malformed, code);
    }

    [Fact]
    public async Task UndecodableDelegationString_IsMalformedWithoutThrowing()
    {
        var (_, envelope) = await ValidEntryAsync();
        Assert.Contains("\"delegation\":null", envelope, StringComparison.Ordinal);
        var bad = envelope.Replace("\"delegation\":null", "\"delegation\":\"" + LoneSurrogate + "\"", StringComparison.Ordinal);

        var ok = CommandEnvelope.TryReadWire(Parse(bad), out var wire, out var code);

        Assert.False(ok);
        Assert.Null(wire);
        Assert.Equal(EnvelopeCodes.Malformed, code);
    }

    [Fact]
    public async Task ProcessorRejectsTheEntryAsMalformedInsteadOfDroppingIt()
    {
        await using var h = EnvelopeHarness.Create();
        var cmd = h.Cmd();
        var entry = JsonSerializer.Serialize(cmd);
        var bad = entry.Replace("\"delegation\":null", "\"delegation\":\"" + LoneSurrogate + "\"", StringComparison.Ordinal);
        Assert.NotEqual(entry, bad);

        await h.Process(JsonSerializer.Deserialize<AgentCommand>(bad)!);

        Assert.Equal(1, h.Rejections(EnvelopeCodes.Malformed));
        Assert.Equal(0, h.Ping.Calls + h.Facts.Calls + h.State.Calls);
        Assert.Empty(h.Backend.Requests);
    }
}
