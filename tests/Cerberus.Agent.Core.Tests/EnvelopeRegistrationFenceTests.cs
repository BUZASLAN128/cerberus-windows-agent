using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class EnvelopeRegistrationFenceTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ProcessorPropagatesRegistrationChangeFromIdentityOrAckWithoutRetrying(bool duringAck)
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        await using var queue = new EnvelopeExecutionQueue(h.Api, h.Store, new[] { h.Ping },
            _ => duringAck ? Task.FromResult(h.AgentId) : throw new AgentRegistrationChangedException(),
            () => false, h.Time, h.Log);
        if (duringAck)
            h.Backend.Respond = (_, _) => throw new AgentRegistrationChangedException();
        var processor = new EnvelopeCommandProcessor(h.Api, new[] { h.Signer.Anchor }, queue, log: h.Log);

        await Assert.ThrowsAsync<AgentRegistrationChangedException>(() => processor.ProcessAsync(new[] { h.Cmd() }, default));

        Assert.Equal(0, h.Ping.Calls);
        Assert.DoesNotContain(h.Log.Lines, line => line.Contains("ack not delivered") || line.Contains("entry failed"));
    }
}
