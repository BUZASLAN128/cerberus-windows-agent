using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>
/// Running executables, one item per distinct image path with the embedded Authenticode signer. Command lines,
/// user names, process ids and arguments are never read. The signer is the subject name of the embedded signing
/// certificate only (no chain building, no network); catalog-signed or unsigned images report null.
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

        var signer = ReadSigner(path);
        lock (CacheLock)
        {
            if (SignerCache.Count >= MaxCacheEntries)
                SignerCache.Clear();
            SignerCache[key] = signer;
        }

        return signer;
    }

    private static string? ReadSigner(string path)
    {
        try
        {
            // SYSLIB0057: X509CertificateLoader cannot read the embedded signer of a signed PE file.
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            var subject = certificate.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(subject) ? null : subject;
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }
}
