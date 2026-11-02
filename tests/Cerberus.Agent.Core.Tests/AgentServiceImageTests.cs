using System.Security.Cryptography;
using System.Text;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Unit/support evidence through the actual canonical identity owner; no registry writes or service launch.
public sealed class AgentServiceImageTests
{
    [Theory]
    [InlineData("matching", true)]
    [InlineData("wrong-process", false)]
    [InlineData("wrong-executable", false)]
    [InlineData("wrong-assembly", false)]
    public void CanonicalIdentity_BindsProcessAndProfileAssemblyBytes(string change, bool expected)
    {
        var root = Path.Combine(Path.GetTempPath(), "service-image-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var executable = Path.Combine(root, "Cerberus.Agent.Service.exe");
            var member = Encoding.UTF8.GetBytes("service assembly fixture");
            WriteImage(executable, member);
            var executableHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable)));
            var assemblyHash = Convert.ToHexString(SHA256.HashData(member));
            var process = change == "wrong-process" ? executable + ".other" : executable;
            if (change == "wrong-executable") executableHash = new string('0', 64);
            if (change == "wrong-assembly") assemblyHash = new string('0', 64);
            if (AgentBuildProfile.IsServer) Assert.False(File.Exists(Path.ChangeExtension(executable, ".dll")));
            Assert.Equal(expected, AgentUpdateLocalService.MatchesCanonicalServiceImage(process, executable, executableHash, assemblyHash));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void ServerAssemblyIdentity_IgnoresAnExternalSidecar()
    {
        if (!AgentBuildProfile.IsServer) return;
        var root = Path.Combine(Path.GetTempPath(), "service-image-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var executable = Path.Combine(root, "Cerberus.Agent.Service.exe");
            var member = Encoding.UTF8.GetBytes("embedded service assembly");
            WriteImage(executable, member);
            File.WriteAllText(Path.ChangeExtension(executable, ".dll"), "untrusted sidecar");
            Assert.True(AgentUpdateLocalService.MatchesCanonicalServiceImage(executable, executable,
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable))), Convert.ToHexString(SHA256.HashData(member))));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void WriteImage(string path, byte[] member)
    {
        if (!AgentBuildProfile.IsServer)
        {
            File.WriteAllText(path, "desktop executable fixture");
            File.WriteAllBytes(Path.ChangeExtension(path, ".dll"), member);
            return;
        }
        // Minimal v6 bundle fixture: the real reader still parses the member table and embedded bytes.
        using var file = File.Create(path);
        using var writer = new BinaryWriter(file, Encoding.UTF8, leaveOpen: false);
        writer.Write((long)(64 + member.Length));
        writer.Write(Convert.FromHexString("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae"));
        writer.Write(new byte[24]);
        writer.Write(member);
        writer.Write((uint)6); writer.Write((uint)0); writer.Write(1); writer.Write("fixture");
        for (var index = 0; index < 5; index++) writer.Write((long)0);
        writer.Write((long)64); writer.Write((long)member.Length); writer.Write((long)0);
        writer.Write((byte)1); writer.Write("Cerberus.Agent.Service.dll");
    }
}
