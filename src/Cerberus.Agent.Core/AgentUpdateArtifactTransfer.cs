namespace Cerberus.Agent.Core;

/// <summary>Transfer bounds come from the validated signed manifest, never an independent artifact size cap.</summary>
public static class AgentUpdateArtifactTransfer
{
    public static long ExpectedLength(AgentUpdateManifest manifest)
    {
        if (!manifest.IsV2 || manifest.ArtifactLength is null or <= 0)
            throw new InvalidOperationException("Update manifest requires a positive signed artifact length.");
        return manifest.ArtifactLength.Value;
    }

    public static void ValidateFileLength(AgentUpdateManifest manifest, long actualBytes)
    {
        if (actualBytes != ExpectedLength(manifest))
            throw new InvalidOperationException("Update artifact length does not match the manifest.");
    }

    internal static void ValidateBitsProgress(long expectedBytes, ulong total, ulong transferred, bool complete)
    {
        if (expectedBytes <= 0 || transferred > (ulong)expectedBytes ||
            (total != ulong.MaxValue && total != (ulong)expectedBytes) ||
            (complete && (total != (ulong)expectedBytes || transferred != (ulong)expectedBytes)))
            throw new InvalidOperationException("BITS update artifact length does not match the manifest.");
    }

    internal static long RequiredFreeSpace(long expectedBytes)
    {
        if (expectedBytes <= 0)
            throw new InvalidOperationException("Update manifest artifact length is invalid.");
        // Download headroom, not an artifact cap or a reservation for the later MSI transaction.
        var headroom = Math.Max(64L * 1024 * 1024, expectedBytes / 20);
        try { return checked(expectedBytes + headroom); }
        catch (OverflowException ex) { throw new InvalidOperationException("Update artifact disk requirement is invalid.", ex); }
    }

    internal static void EnsureDiskSpace(string destination, long expectedBytes, Func<string, long>? availableBytes = null)
    {
        var required = RequiredFreeSpace(expectedBytes);
        long available;
        try
        {
            var volume = Path.GetPathRoot(Path.GetFullPath(destination))
                ?? throw new IOException("Update destination volume is missing.");
            available = (availableBytes ?? (root => new DriveInfo(root).AvailableFreeSpace))(volume);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
        {
            throw new InvalidOperationException("Update artifact disk space could not be verified.", ex);
        }
        if (available < required)
            throw new InvalidOperationException("Insufficient disk space for the update artifact.");
    }
}
