using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cerberus.Agent.Core;

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

    private readonly record struct SignerKey(string Path, long LastWriteTicks, long Length);

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

    private static string? ReadSignerCached(string path)
    {
        SignerKey key;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
                return null;
            key = new SignerKey(path, info.LastWriteTimeUtc.Ticks, info.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }

        lock (CacheLock)
        {
            if (SignerCache.TryGetValue(key, out var cached))
                return cached;
        }

        if (!TryReadSigner(path, out var signer))
            return null; // transient I/O error: not cached, retried next cycle

        // The image must be unchanged since the key was taken, otherwise the result belongs to another file version.
        if (!SameFile(path, key))
            return signer;

        lock (CacheLock)
        {
            if (SignerCache.Count >= MaxCacheEntries)
                SignerCache.Clear();
            SignerCache[key] = signer;
        }

        return signer;
    }

    private static bool SameFile(string path, SignerKey key)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists && info.LastWriteTimeUtc.Ticks == key.LastWriteTicks && info.Length == key.Length;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
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
            if (!AgentUpdateAuthenticode.TryGetValidSignerSubject(path, out _))
                return true;
            // SYSLIB0057: X509CertificateLoader cannot read the embedded signer of a signed PE file.
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            var subject = certificate.GetNameInfo(X509NameType.SimpleName, false);
            signer = string.IsNullOrWhiteSpace(subject) ? null : subject;
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
