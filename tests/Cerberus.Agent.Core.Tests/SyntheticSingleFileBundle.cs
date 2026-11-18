using System.Text;

namespace Cerberus.Agent.Core.Tests;

internal static class SyntheticSingleFileBundle
{
    private static readonly byte[] Signature =
        Convert.FromHexString("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae");

    internal static void Write(string path, params (string Name, byte Kind)[] entries)
    {
        using var stream = File.Create(path);
        using var writer = new BinaryWriter(stream, Encoding.UTF8);
        writer.Write(0L);
        writer.Write(Signature);
        var dataOffset = stream.Position;
        foreach (var _ in entries)
            writer.Write((byte)1);
        var headerOffset = stream.Position;
        writer.Write(6u);
        writer.Write(0u);
        writer.Write(entries.Length);
        writer.Write("fixture");
        writer.Write(0L); writer.Write(0L); // deps.json location
        writer.Write(0L); writer.Write(0L); // runtimeconfig.json location
        writer.Write(0UL);
        foreach (var (name, kind) in entries)
        {
            writer.Write(dataOffset++);
            writer.Write(1L);
            writer.Write(0L);
            writer.Write(kind);
            writer.Write(name);
        }
        stream.Position = 0;
        writer.Write(headerOffset);
    }
}
