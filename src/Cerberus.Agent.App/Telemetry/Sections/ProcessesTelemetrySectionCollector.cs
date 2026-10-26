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

    internal readonly record struct SignerKey(string Path, ulong VolumeSerial, ulong FileIdLow, ulong FileIdHigh, long Usn);

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
    /// This is only a pre-filter: the path can change after the check, so <see cref="LocalImageFile.TryOpen"/>
    /// refuses reparse points again in the open itself.
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

    internal static string? ReadSignerCached(string path)
    {
        // Cheap pre-filter: never open an image outside a local fixed disk; the path is reported, the signer stays null.
        if (!IsLocalFixedPath(path))
            return null;

        // One open that cannot traverse a reparse point; identity and signature are both read through it, so a
        // component swapped after the pre-filter fails the open rather than redirecting it.
        using var handle = LocalImageFile.TryOpen(path);
        if (handle is null)
            return null;

        return SignerFor(handle, path, TryGetKey, TryReadSigner);
    }

    internal delegate bool KeyReader(SafeFileHandle handle, string path, out SignerKey key);

    internal delegate bool SignerReader(SafeFileHandle handle, string path, out string? signer);

    /// <summary>
    /// Cache lookup, verification and store around one handle. Without a key (no change journal, unreadable
    /// identity) the image is verified every time and nothing is cached.
    /// </summary>
    internal static string? SignerFor(SafeFileHandle handle, string path, KeyReader keyOf, SignerReader read)
    {
        if (!keyOf(handle, path, out var key))
        {
            // Not cacheable: report the verified signer for this call only.
            return read(handle, path, out var uncached) ? uncached : null;
        }

        lock (CacheLock)
        {
            if (SignerCache.TryGetValue(key, out var cached))
                return cached;
        }

        if (!read(handle, path, out var signer))
            return null; // transient I/O error: not cached, retried next cycle

        // The identity (including the USN, which any data, attribute or timestamp change advances) must be unchanged
        // after verification; otherwise the verified signer may belong to other content and is not cached.
        if (!keyOf(handle, path, out var after) || after != key)
            return null;

        lock (CacheLock)
        {
            if (SignerCache.Count >= MaxCacheEntries)
                SignerCache.Clear();
            SignerCache[key] = signer;
        }

        return signer;
    }

    /// <summary>
    /// Identity read through the open handle that the file owner cannot restore: volume serial, 128-bit file id and
    /// the current USN. Size and last write time are left out, since SetFileTime can put them back after an in-place
    /// edit. False (nothing is cached) when the id or a non-zero USN cannot be read, e.g. no change journal.
    /// </summary>
    internal static bool TryGetKey(SafeFileHandle handle, string path, out SignerKey key)
    {
        key = default;
        var id = new byte[24]; // FILE_ID_INFO: VolumeSerialNumber (8), FileId (16)
        if (!GetFileInformationByHandleEx(handle, FileIdInfoClass, id, (uint)id.Length))
            return false;
        if (!TryReadUsn(handle, out var usn))
            return false;
        key = new SignerKey(path, BitConverter.ToUInt64(id, 0), BitConverter.ToUInt64(id, 8), BitConverter.ToUInt64(id, 16), usn);
        return true;
    }

    private static bool TryReadUsn(SafeFileHandle handle, out long usn)
    {
        var buffer = new byte[4096];
        usn = 0;
        return DeviceIoControl(handle, FsctlReadFileUsnData, IntPtr.Zero, 0, buffer, (uint)buffer.Length, out var returned, IntPtr.Zero)
            && TryParseUsn(buffer, (int)returned, out usn);
    }

    /// <summary>
    /// Usn of the first USN_RECORD_V2/V3 in <paramref name="buffer"/> (V2 at offset 24, V3 at offset 32); false for a
    /// short or inconsistent record, another version, or a USN of zero or below (no journal entry for the file).
    /// </summary>
    internal static bool TryParseUsn(byte[] buffer, int length, out long usn)
    {
        usn = 0;
        if (length < 32 || length > buffer.Length)
            return false;
        var recordLength = BitConverter.ToUInt32(buffer, 0);
        var major = BitConverter.ToUInt16(buffer, 4);
        var offset = major switch { 2 => 24, 3 => 32, _ => -1 };
        if (offset < 0 || recordLength > length || recordLength < offset + 8)
            return false;
        usn = BitConverter.ToInt64(buffer, offset);
        return usn > 0;
    }

    private const int FileIdInfoClass = 18;
    private const uint FsctlReadFileUsnData = 0x000900EB;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, [Out] byte[] info, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle handle, uint code, IntPtr input, uint inputSize, [Out] byte[] output, uint outputSize, out uint returned, IntPtr overlapped);

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
    private static bool TryReadSigner(SafeFileHandle handle, string path, out string? signer)
    {
        signer = null;
        try
        {
            // The subject is the certificate Subject (full distinguished name) from the signature WinVerifyTrust accepted.
            if (!AgentUpdateAuthenticode.TryGetValidSignerSubject(handle, path, out var subject))
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
