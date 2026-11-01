using System.Reflection;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Installer.Helper;

internal static partial class Program
{
    private static void ValidateRuntimeFiles(string runtime)
    {
        runtime = Path.GetFullPath(runtime);
        string Metadata(string key) => typeof(Program).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .SingleOrDefault(attribute => attribute.Key == key)?.Value ?? "";
        var pins = Metadata("AgentUpdateAllowedSignerKeyIdentity");
        var channel = Metadata("AgentReleaseChannel");
        foreach (var name in new[] { "Cerberus.Agent.exe", "Cerberus.Agent.Service.exe", "Cerberus.Agent.Updater.exe" })
        {
            var path = Path.Combine(runtime, name);
            AgentUpdateSecurity.ValidateInstalledServiceSource(path, runtime);
            AgentUpdateAuthenticode.Verify(path, channel, pins, allowUnsignedDevBuild: false);
            _ = AgentSingleFileBundle.ReadAssembly(path, Path.GetFileNameWithoutExtension(path) + ".dll");
        }
    }
}
