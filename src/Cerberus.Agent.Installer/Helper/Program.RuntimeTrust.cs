using System.Reflection;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Installer.Helper;

internal static partial class Program
{
    private static readonly string[] RuntimeExecutables = ["Cerberus.Agent.exe", "Cerberus.Agent.Service.exe", "Cerberus.Agent.Updater.exe"];

    private static void ValidateRuntimeAuthority(string runtime)
    {
        runtime = Path.GetFullPath(runtime);
        AgentUpdateSecurity.ValidateProtectedTree(runtime);
        string Metadata(string key) => typeof(Program).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .SingleOrDefault(attribute => attribute.Key == key)?.Value ?? "";
        var pins = Metadata("AgentUpdateAllowedSignerKeyIdentity");
        var channel = Metadata("AgentReleaseChannel");
        var allowLabRuntime = Cerberus.Agent.App.Updates.AgentUpdateLabRuntimeAdmission.AllowRuntime(runtime,
            _labProduct, _labVersion, _labTransaction);
        foreach (var name in RuntimeExecutables)
        {
            var path = Path.Combine(runtime, name);
            AgentUpdateSecurity.ValidateInstalledServiceSource(path, runtime);
            AgentUpdateAuthenticode.Verify(path, channel, pins, allowUnsignedDevBuild: allowLabRuntime);
        }
    }

    private static bool ValidateServerRuntimeImage(string runtime, string executableHash, HealthTrace trace)
    {
        runtime = Path.GetFullPath(runtime);
        var ready = AgentInstallerServiceImageGate.Validate(runtime,
            () => { trace.Phase = AgentInstallerHealthPhase.RuntimePath; ValidateRuntimeAuthority(runtime); },
            () =>
            {
                trace.Phase = AgentInstallerHealthPhase.ServiceExecutableHash;
                return MatchesHash(Path.Combine(runtime, "Cerberus.Agent.Service.exe"), runtime, executableHash);
            },
            serviceReady =>
            {
                trace.Phase = AgentInstallerHealthPhase.RuntimePath;
                foreach (var name in RuntimeExecutables)
                {
                    if (!serviceReady && name == "Cerberus.Agent.Service.exe") continue;
                    _ = AgentSingleFileBundle.ReadAssembly(Path.Combine(runtime, name), Path.GetFileNameWithoutExtension(name) + ".dll");
                }
            }, ReadPendingRenames);
        if (!ready) Console.Error.WriteLine("Cerberus installer service image verification deferred: a restart is pending.");
        return ready;
    }
}
