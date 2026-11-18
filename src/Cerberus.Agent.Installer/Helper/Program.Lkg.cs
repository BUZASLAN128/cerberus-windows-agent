using Cerberus.Agent.Core;

namespace Cerberus.Agent.Installer.Helper;

internal static partial class Program
{
    private static int RequireRollbackGrant(string[] args)
    {
        const int installFailure = 1603;
        if (!OperatingSystem.IsWindows() || !AgentUpdateSecurity.IsLocalSystem() ||
            args.Length < 2 || !Guid.TryParse(args[1], out var product) || product == Guid.Empty)
            return installFailure;

        var root = AgentUpdateSecurity.DefaultPrivilegedRoot;
        var result = !AgentInstallerInvocation.TryParse(args, out var invocation)
            ? AgentUpdateRollbackGrantResult.Denied("grant_parse")
            : AgentUpdateRollbackGrant.Consume(root, AgentBuildProfile.IsServer, product,
                invocation!.Version, args[6], args[7], args[8]);
        try
        {
            AgentUpdateRollbackGrant.WriteResult(root, product, result, DateTimeOffset.UtcNow);
            return result.Allowed ? 0 : installFailure;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return installFailure;
        }
    }
}
