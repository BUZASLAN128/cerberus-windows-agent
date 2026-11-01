using Cerberus.Agent.App;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentStateRevokeGuardTests
{
    [Theory]
    [InlineData("legacy", null)]
    [InlineData("bound", null)]
    [InlineData("other", null)]
    [InlineData("unreadable", null)]
    [InlineData("empty", null)]
    public async Task DirectVerifiedEnrollmentClearsOnlyMatchingLegacyRevoke(string kind, string? expectedCode)
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir, productionBinding: true);
        var path = Path.Combine(_dir, "direct-signed-state.json");
        var state = new AgentSignedStateStore(path);
        var original = f.Store.Load("agent-a");
        if (kind == "unreadable")
            await File.WriteAllTextAsync(path, "{invalid test-owned state");
        else if (kind != "empty")
            Assert.True(state.TrySave(kind == "bound" ? original : original with
            {
                PendingRevoke = original.PendingRevoke! with { Registration = null },
            }));
        var before = await f.Lifecycle.LoadAsync(default);
        var nonce = Guid.NewGuid().ToString("N");
        var marker = new AgentEnrollmentMarker("agent.enrollment-promotion.v1", before.Generation,
            kind == "other" ? "agent-b" : "agent-a", "t1", new string('a', 64), nonce,
            DateTimeOffset.UtcNow.AddMinutes(5));
        var adopted = await f.Lifecycle.CompleteEnrollmentAsync(before.Generation, nonce, default);

        var code = WindowsHeadlessHost.CompleteDirectEnrollment(marker, before, adopted, state);

        Assert.Equal(expectedCode, code);
        if (kind is "bound" or "other")
            Assert.NotNull(new AgentSignedStateStore(path).Load("agent-a").PendingRevoke);
        if (kind == "legacy")
            Assert.Null(new AgentSignedStateStore(path).Load("agent-a").PendingRevoke);
        if (kind == "unreadable")
            Assert.True(state.IsQuarantined("agent-a"));
        Assert.False(f.Secrets.Cleared);
    }
}
