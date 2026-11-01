using System.Buffers.Binary;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentSingleFileBundleTests
{
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
