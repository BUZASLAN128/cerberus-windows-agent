namespace Cerberus.Agent.Core;

/// <summary>Orders the installer's authority, service image and bundle checks without excusing other runtime failures.</summary>
public static class AgentInstallerServiceImageGate
{
    public static bool Validate(string runtime, Action validateAuthority, Func<bool> serviceExecutableMatches,
        Action<bool> validateBundles, Func<IEnumerable<string>> pendingRenames)
    {
        validateAuthority();
        // A false result represents only a byte mismatch. Authority, read and cancellation errors must propagate.
        var serviceReady = serviceExecutableMatches();
        if (!serviceReady && !AgentUpdateRollbackPolicy.PendingRebootExcuses(
            AgentInstallerHealthPhase.ServiceExecutableHash, false, pendingRenames(), runtime))
            throw new InvalidOperationException("Installed service executable hash does not match the package.");
        // Launcher/updater bundles are always checked. Only the verified, queued old service image may remain split.
        validateBundles(serviceReady);
        return serviceReady;
    }
}
