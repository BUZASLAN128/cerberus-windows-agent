using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class GovernedWindowsMutationGuardTests
{
    [Fact]
    public void ValidateOrDeny_DeniesWhenLocalPolicyDisabled()
    {
        var command = new AgentCommand(
            Id: "cmd-1",
            Type: "windows.user.create",
            IdempotencyKey: "idem-1",
            Payload: new { approval_id = "approval-1", audit_correlation_id = "audit-1" });

        var result = GovernedWindowsMutationGuard.ValidateOrDeny(command, enabled: false);

        Assert.Equal("DENIED", result.Status);
        Assert.Contains("disabled", result.Stderr);
    }

    [Fact]
    public void ValidateOrDeny_RequiresApprovalAndAuditCorrelation()
    {
        var command = new AgentCommand(
            Id: "cmd-1",
            Type: "windows.user.create",
            IdempotencyKey: "idem-1",
            Payload: new { user = "example" });

        var result = GovernedWindowsMutationGuard.ValidateOrDeny(command, enabled: true);

        Assert.Equal("DENIED", result.Status);
        Assert.Contains("approval_id", result.Stderr);
    }

    [Fact]
    public async Task Handler_DoesNotMutateEvenAfterGuardUntilExecutorExists()
    {
        var handler = new GovernedWindowsMutationHandler("windows.user.disable", enabled: true);
        var command = new AgentCommand(
            Id: "cmd-1",
            Type: "windows.user.disable",
            IdempotencyKey: "idem-1",
            Payload: new { approval_id = "approval-1", audit_correlation_id = "audit-1" });

        var result = await handler.HandleAsync(command, CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Contains("not implemented", result.Stderr);
    }
}
