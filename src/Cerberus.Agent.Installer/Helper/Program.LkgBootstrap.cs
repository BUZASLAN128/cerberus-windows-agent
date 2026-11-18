using System.Reflection;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Installer.Helper;

internal static partial class Program
{
    private static int RunLkgAction(AgentInstallerInvocation invocation, string runtimeDirectory)
    {
        if (!OperatingSystem.IsWindows() || !AgentBuildProfile.IsServer || !AgentUpdateSecurity.IsLocalSystem() ||
            invocation.ProductCode == Guid.Empty)
            return 1603;

        switch (invocation.Operation)
        {
            case "lkg-bootstrap":
                BootstrapLkgWatch(runtimeDirectory, invocation.Version);
                break;
            case "unregister-watch-task":
                AgentUpdateWatchTask.Delete();
                break;
            case "reregister-watch-task":
                AgentUpdateWatchTask.CreateIfAbsent();
                break;
            default:
                return 1603;
        }
        return 0;
    }

    private static void BootstrapLkgWatch(string runtimeDirectory, string version)
    {
        string Metadata(string name) => typeof(Program).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .SingleOrDefault(attribute => attribute.Key == name)?.Value ?? "";
        var channel = Metadata("AgentReleaseChannel");
        var policy = AgentUpdateLabPolicy.Parse(Metadata(AgentUpdateLabPolicy.MetadataName), channel,
            Metadata("AllowUnsignedDevBuild") == "true", AgentBuildProfile.IsServer);
        var store = new AgentUpdateLkgStore(AgentUpdateSecurity.DefaultPrivilegedRoot);
        store.BootstrapWatchHost(runtimeDirectory, version, channel, Metadata("AgentUpdateAllowedSignerKeyIdentity"),
            DateTimeOffset.UtcNow, AgentInstalledProductVersion.Read, policy?.CampaignId, policy is null ? null :
                (updaterVersion, sha256) => AgentUpdateLabRuntimeAdmission.IsAdmittedLabArtifact("updater", updaterVersion, sha256));
    }
}
