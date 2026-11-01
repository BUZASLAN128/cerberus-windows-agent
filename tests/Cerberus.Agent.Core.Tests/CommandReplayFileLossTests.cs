using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class CommandReplayFileLossTests
{
    [Fact]
    public async Task CompletedEnvelopeCannotRunAgainAfterFileLossAndRestartEvenInTheSameSecond()
    {
        await using var h = EnvelopeHarness.Create();
        var entry = h.Cmd();
        await h.Processor.ProcessAsync(new[] { entry }, default);
        await Wait.UntilAsync(() => h.Ping.Calls == 1 && h.Store.Find(h.AgentId, entry.Id)?.State == EnvelopeRecordStates.Done,
            "first command completed");
        await h.Queue.StopAsync();
        File.Delete(h.StorePath);
        var reset = new CommandReplayStore(h.StorePath, h.Time, enrollmentEstablished: true);
        Assert.True(reset.IsAvailable);
        var restarted = new CommandReplayStore(h.StorePath, h.Time, enrollmentEstablished: true);
        Assert.Equal(h.Time.GetUtcNow().ToUnixTimeSeconds(), restarted.ResetAt);
        var signed = new CommandEnvelopeVerifier(new[] { h.Signer.Anchor }, new HashSet<string> { "ping" }).VerifyEntry(entry, h.AgentId);
        Assert.True(signed.Passed);
        var check = CommandEnvelopeVerifier.CheckReplayWindow(signed.Envelope!, h.Time.GetUtcNow().ToUnixTimeSeconds(), restarted.ResetAt, false);
        Assert.Equal(EnvelopeCodes.IssuedBeforeReset, check.Code);
        await using var queue = new EnvelopeExecutionQueue(h.Api, restarted, new[] { h.Ping },
            _ => Task.FromResult(h.AgentId), () => false, h.Time);
        queue.Start();
        var processor = new EnvelopeCommandProcessor(h.Api, new[] { h.Signer.Anchor }, queue, new HashSet<string> { "ping" });
        await processor.ProcessAsync(new[] { entry }, default);
        Assert.Equal(1, h.Ping.Calls);
    }
}
