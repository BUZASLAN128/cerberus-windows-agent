using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

public static class AgentServiceImage
{
    public static string ReadAssemblySha256(string executable)
    {
        using Stream assembly = AgentBuildProfile.IsServer
            ? new MemoryStream(AgentSingleFileBundle.ReadAssembly(executable, "Cerberus.Agent.Service.dll"), writable: false)
            : File.OpenRead(Path.ChangeExtension(executable, ".dll"));
        return Convert.ToHexString(SHA256.HashData(assembly)).ToLowerInvariant();
    }
}
