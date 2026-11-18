using System.Buffers.Binary;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentSingleFileBundleTests
{
    [Fact]
    public void ReadEntriesPreservesNamesKindsAndOrder()
    {
        var path = Path.Combine(Path.GetTempPath(), "bundle-entries-" + Guid.NewGuid().ToString("N"));
        (string Name, byte Kind)[] expected = [("Agent.DLL", 1), ("unknown.dll", 0), ("Native.DLL", 2), ("agent.deps.json", 3)];
        try
        {
            SyntheticSingleFileBundle.Write(path, expected);
            Assert.Equal(expected, AgentSingleFileBundle.ReadEntries(path).Select(entry => (entry.Name, entry.Kind)));
            Assert.Equal(new byte[] { 1 }, AgentSingleFileBundle.ReadAssembly(path, "Agent.DLL"));
            Assert.Throws<InvalidDataException>(() => AgentSingleFileBundle.ReadAssembly(path, "agent.dll"));
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)2)]
    public void ReadAssemblyRefusesNonManagedEntry(byte kind)
    {
        var path = Path.Combine(Path.GetTempPath(), "bundle-kind-" + Guid.NewGuid().ToString("N"));
        try
        {
            SyntheticSingleFileBundle.Write(path, ("entry.dll", kind));
            Assert.Throws<InvalidDataException>(() => AgentSingleFileBundle.ReadAssembly(path, "entry.dll"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ReadEntriesListsDuplicateNamesAndReadAssemblyRefusesAmbiguousMatch()
    {
        var path = Path.Combine(Path.GetTempPath(), "bundle-duplicates-" + Guid.NewGuid().ToString("N"));
        try
        {
            SyntheticSingleFileBundle.Write(path, ("duplicate.dll", 1), ("duplicate.dll", 1), ("other.dll", 1));
            Assert.Equal(new[] { "duplicate.dll", "duplicate.dll", "other.dll" },
                AgentSingleFileBundle.ReadEntries(path).Select(entry => entry.Name));
            Assert.Throws<InvalidDataException>(() => AgentSingleFileBundle.ReadAssembly(path, "duplicate.dll"));
            Assert.Equal(new byte[] { 1 }, AgentSingleFileBundle.ReadAssembly(path, "other.dll"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void OrdinaryManagedAssemblyCannotStandInForBundle()
    {
        var path = typeof(AgentSingleFileBundle).Assembly.Location;
        Assert.False(AgentSingleFileBundle.IsBundle(path));
        Assert.Throws<InvalidDataException>(() => AgentSingleFileBundle.ReadAssembly(path, "Cerberus.Agent.Core.dll"));
    }

    [Fact]
    public void ForgedHeaderOffsetFailsClosedWithoutExtraction()
    {
        var path = Path.Combine(Path.GetTempPath(), "invalid-bundle-" + Guid.NewGuid().ToString("N"));
        var bytes = new byte[64];
        BinaryPrimitives.WriteInt64LittleEndian(bytes, long.MaxValue);
        Convert.FromHexString("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae").CopyTo(bytes, 8);
        File.WriteAllBytes(path, bytes);
        try
        {
            Assert.Throws<InvalidDataException>(() => AgentSingleFileBundle.IsBundle(path));
            Assert.Throws<InvalidDataException>(() => AgentSingleFileBundle.ReadAssembly(path, "../entry.dll"));
        }
        finally { File.Delete(path); }
    }
}
