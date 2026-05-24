using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static class UpdateApplyMode
{
    public static async Task<int> RunAsync(string planPath, string? targetPath, CancellationToken ct)
    {
        if (!Elevation.IsAdministrator())
            throw new InvalidOperationException("Administrator privileges are required to apply a staged agent update.");

        var target = string.IsNullOrWhiteSpace(targetPath)
            ? Environment.ProcessPath
            : targetPath;
        if (string.IsNullOrWhiteSpace(target))
            throw new InvalidOperationException("Target executable path could not be resolved.");

        await AgentUpdateStager
            .ApplyPlanAsync(planPath, target, AgentUpdateStager.DefaultStagingRoot, target, ct)
            .ConfigureAwait(false);
        return 0;
    }
}
