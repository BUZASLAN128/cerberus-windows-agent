using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace Cerberus.Agent.Core;

/// <summary>Reads managed bytes from the .NET 6+ bundle without loading or extracting executable code.</summary>
public static class AgentSingleFileBundle
{
    // dotnet/runtime HostWriter bundle signature; the preceding Int64 points at Manifest.Write's header.
    private static readonly byte[] Signature = Convert.FromHexString("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae");
    private const int MaxMemberBytes = 64 * 1024 * 1024;

    public static bool IsBundle(string path)
    {
        using var file = File.OpenRead(path);
        return FindHeader(file) != 0;
    }

    public static byte[] ReadAssembly(string bundlePath, string assemblyName)
    {
        using var file = File.OpenRead(bundlePath);
        var header = FindHeader(file);
        if (header == 0) throw new InvalidDataException("The executable is not a single-file bundle.");
        file.Position = header;
        using var reader = new BinaryReader(file, Encoding.UTF8, leaveOpen: true);
        if (reader.ReadUInt32() != 6 || reader.ReadUInt32() != 0)
            throw new InvalidDataException("Unsupported bundle format.");
        var count = reader.ReadInt32();
        if (count is < 1 or > 4096) throw new InvalidDataException("Invalid bundle entry count.");
        _ = ReadString(reader, 128); // Extraction ID, not an authority input.
        _ = reader.ReadInt64(); _ = reader.ReadInt64(); // deps.json location
        _ = reader.ReadInt64(); _ = reader.ReadInt64(); // runtimeconfig.json location
        if (reader.ReadUInt64() != 0)
            throw new InvalidDataException("Managed extraction compatibility mode is not allowed.");
        long selectedOffset = -1;
        var selectedSize = 0;
        for (var index = 0; index < count; index++)
        {
            var offset = reader.ReadInt64();
            var size = reader.ReadInt64();
            var compressed = reader.ReadInt64();
            var kind = reader.ReadByte();
            var name = ReadString(reader, 4096);
            if (offset < 0 || offset > header || size < 0 || size > header - offset || compressed != 0)
                throw new InvalidDataException("Invalid or compressed bundle entry.");
            if (!string.Equals(name, assemblyName, StringComparison.Ordinal)) continue;
            if (selectedOffset >= 0 || kind != 1 || size is <= 0 or > MaxMemberBytes)
                throw new InvalidDataException("Invalid managed bundle entry.");
            selectedOffset = offset;
            selectedSize = checked((int)size);
        }
        if (selectedOffset < 0) throw new InvalidDataException("Required assembly is not embedded in the bundle.");
        file.Position = selectedOffset;
        var bytes = new byte[selectedSize];
        file.ReadExactly(bytes);
        return bytes;
    }

    private static long FindHeader(FileStream file)
    {
        // The self-contained Windows host includes hostfxr and is larger than the thin apphost.
        var prefix = new byte[(int)Math.Min(file.Length, 32 * 1024 * 1024)];
        file.ReadExactly(prefix);
        var marker = prefix.AsSpan().IndexOf(Signature);
        if (marker < 8) return 0;
        var header = BinaryPrimitives.ReadInt64LittleEndian(prefix.AsSpan(marker - 8, 8));
        if (header == 0) return 0; // SDK's ordinary, unbundled apphost placeholder.
        if (header < marker + Signature.Length || header >= file.Length)
            throw new InvalidDataException("Invalid bundle header location.");
        return header;
    }

    private static string ReadString(BinaryReader reader, int limit)
    {
        var length = reader.Read7BitEncodedInt();
        if (length < 0 || length > limit) throw new InvalidDataException("Invalid bundle string length.");
        var bytes = reader.ReadBytes(length);
        if (bytes.Length != length) throw new EndOfStreamException();
        return new UTF8Encoding(false, true).GetString(bytes);
    }
}
