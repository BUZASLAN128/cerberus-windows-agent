using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Cerberus.Agent.Core;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>
/// Running executables, one item per distinct image path with the embedded Authenticode signer. Command lines,
/// process ids and arguments are never read; the image path is reported as is and can contain a user profile
/// folder name. The signer is the simple subject name of the embedded signing certificate, reported only when
/// WinVerifyTrust accepts the signature (no network, cached revocation data only); catalog-signed, unsigned or
/// untrusted images report null.
/// </summary>
internal sealed class ProcessesTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    internal const int MaxItems = 400;
    internal const int MaxCacheEntries = 2048;

    /// <summary>One running process: <c>Path</c> is null when the image path cannot be read.</summary>
    internal sealed record RawProcess(string? Path);

    private readonly record struct SignerKey(string Path, long LastWriteTicks, long Length, uint VolumeSerial, long FileIndex);

    private static readonly Dictionary<SignerKey, string?> SignerCache = new();
    private static readonly object CacheLock = new();

    public string SectionName => "processes";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
        => ValueTask.FromResult(Build(Read(ct), ReadSignerCached, ct));

    /// <summary>
    /// <c>count</c> = number of distinct image paths seen (ordinal, case-insensitive) plus the number of processes
    /// whose path could not be read. Unreadable processes are counted individually and never listed.
    /// </summary>
    internal static object Build(IEnumerable<RawProcess> raw, Func<string, string?> signerOf, CancellationToken ct = default)
    {
        var unreadable = 0;
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in raw)
        {
            if (string.IsNullOrWhiteSpace(process.Path))
                unreadable++;
            else
                paths.Add(process.Path);
        }

        var ordered = paths
            .Select(p => (Path: p, Name: System.IO.Path.GetFileName(p)))
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Name, StringComparer.Ordinal)
            .ThenBy(p => p.Path, StringComparer.OrdinalIgnoreCase)
            .ThenBy(p => p.Path, StringComparer.Ordinal)
            .ToArray();

        var items = new List<object>(Math.Min(ordered.Length, MaxItems));
        foreach (var (path, name) in ordered.Take(MaxItems))
        {
            ct.ThrowIfCancellationRequested();
            items.Add(new
            {
                name = ServerFactText.Clean(name, 260),
                path = ServerFactText.Clean(path, 520),
                signer = ServerFactText.CleanOrNull(signerOf(path), 200),
            });
        }

        return new
        {
            status = "ok",
            count = paths.Count + unreadable,
            items = items.ToArray(),
            truncated = ordered.Length > MaxItems,
        };
    }

    private static List<RawProcess> Read(CancellationToken ct)
    {
        var result = new List<RawProcess>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                ct.ThrowIfCancellationRequested();
                result.Add(new RawProcess(ReadImagePath(process)));
            }
        }

        return result;
    }

    private static string? ReadImagePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>
    /// True only for a drive-letter path on a fixed local disk. UNC, device (<c>\\?\</c>, <c>\\.\</c>), relative and
    /// removable/network/optical paths are rejected so the service account never opens a file a user pointed it at
    /// (an SMB open would send the machine account's NTLM credentials to that host).
    /// Reparse points (symlinks, junctions) anywhere in the path are rejected too, since they can lead to a share.
    /// </summary>
    internal static bool IsLocalFixedPath(string? path, Func<string, DriveType>? driveTypeOf = null, Func<string, FileAttributes>? attributesOf = null)
    {
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
            return false;
        try
        {
            if (!System.IO.Path.IsPathFullyQualified(path))
                return false;
            var root = System.IO.Path.GetPathRoot(path);
            if (root is not { Length: >= 3 } || !char.IsAsciiLetter(root[0]) || root[1] != ':')
                return false;
            if ((driveTypeOf ?? (r => new DriveInfo(r).DriveType))(root) != DriveType.Fixed)
                return false;

            // Top-down: a deeper component is only stat'ed once its parent is known not to be a reparse point.
            var stat = attributesOf ?? File.GetAttributes;
            var full = System.IO.Path.GetFullPath(path);
            var current = root;
            foreach (var segment in full[root.Length..].Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries))
            {
                current = System.IO.Path.Combine(current, segment);
                if ((stat(current) & FileAttributes.ReparsePoint) != 0)
                    return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or NotSupportedException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static string? ReadSignerCached(string path)
    {
        // Never open an image outside a local fixed disk: the path is reported, the signer stays null.
        if (!IsLocalFixedPath(path))
            return null;

        // No identity (file missing, unreadable, not NTFS-like): nothing is reported or cached.
        if (!TryGetKey(path, out var key))
            return null;

        lock (CacheLock)
        {
            if (SignerCache.TryGetValue(key, out var cached))
                return cached;
        }

        if (!TryReadSigner(path, out var signer))
            return null; // transient I/O error: not cached, retried next cycle

        // The file must still be the same one (volume, file index, size, last write) after verification;
        // otherwise the verified signer may belong to another file and nothing is reported or cached.
        if (!TryGetKey(path, out var after) || after != key)
            return null;

        lock (CacheLock)
        {
            if (SignerCache.Count >= MaxCacheEntries)
                SignerCache.Clear();
            SignerCache[key] = signer;
        }

        return signer;
    }

    private static bool TryGetKey(string path, out SignerKey key)
    {
        key = default;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (!GetFileInformationByHandle(stream.SafeFileHandle, out var info))
                return false;
            var index = ((long)info.FileIndexHigh << 32) | info.FileIndexLow;
            var written = ((long)info.LastWriteTime.High << 32) | info.LastWriteTime.Low;
            var length = ((long)info.FileSizeHigh << 32) | info.FileSizeLow;
            key = new SignerKey(path, written, length, info.VolumeSerialNumber, index);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low;
        public uint High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FileTime CreationTime;
        public FileTime LastAccessTime;
        public FileTime LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation info);

    /// <summary>
    /// Simple name of a distinguished name: CN, else O, else OU. Multi-valued RDNs are skipped; null when nothing
    /// matches or the subject does not parse (never the whole DN).
    /// </summary>
    internal static string? SimpleNameFromSubject(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
            return null;
        try
        {
            string? organization = null;
            string? unit = null;
            foreach (var rdn in new X500DistinguishedName(subject).EnumerateRelativeDistinguishedNames())
            {
                if (rdn.HasMultipleElements)
                    continue;
                var type = rdn.GetSingleElementType().Value;
                var value = rdn.GetSingleElementValue();
                if (string.IsNullOrWhiteSpace(value))
                    continue;
                if (type == "2.5.4.3")
                    return value;
                if (type == "2.5.4.10")
                    organization ??= value;
                else if (type == "2.5.4.11")
                    unit ??= value;
            }

            return organization ?? unit;
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Signer subject only for an Authenticode signature that WinVerifyTrust accepts (digest and chain verified,
    /// cache-only revocation, no network). Unsigned, catalog-signed or untrusted images report null.
    /// Returns false on an I/O error so the caller does not cache the miss.
    /// </summary>
    private static bool TryReadSigner(string path, out string? signer)
    {
        signer = null;
        try
        {
            // The subject is the certificate Subject (full distinguished name) from the signature WinVerifyTrust accepted.
            if (!AgentUpdateAuthenticode.TryGetValidSignerSubject(path, out var subject))
                return true;
            signer = SimpleNameFromSubject(subject);
            return true;
        }
        catch (CryptographicException)
        {
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }
}
