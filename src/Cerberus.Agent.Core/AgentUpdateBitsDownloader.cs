using System.Runtime.InteropServices;

namespace Cerberus.Agent.Core;

/// <summary>
/// Downloads update artifacts through the Windows Background Intelligent Transfer
/// Service. The service is intentionally the only production download path for MSI
/// payloads; an unavailable BITS service is a hard failure.
/// </summary>
public sealed class AgentUpdateBitsDownloader
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    public async Task DownloadAsync(
        Uri source,
        string destination,
        long maxBytes,
        CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("Windows BITS is unavailable.");
        if (source is null || !source.IsAbsoluteUri || !string.Equals(source.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update artifact URL is not a trusted HTTPS URL.");
        if (string.IsNullOrWhiteSpace(destination))
            throw new ArgumentException("BITS destination is required.", nameof(destination));
        if (maxBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxBytes));

        var fullDestination = Path.GetFullPath(destination);
        Directory.CreateDirectory(Path.GetDirectoryName(fullDestination) ?? throw new InvalidOperationException("BITS destination directory is missing."));
        TryDelete(fullDestination);

        IBackgroundCopyManager? manager = null;
        IBackgroundCopyJob? job = null;
        Guid jobId = default;
        var completed = false;
        try
        {
            manager = (IBackgroundCopyManager)new BackgroundCopyManager();
            Check(manager.CreateJob(
                "Cerberus Agent update",
                BackgroundCopyJobType.Download,
                out jobId,
                out job), "BITS job creation failed.");
            Check(job.AddFile(source.AbsoluteUri, fullDestination), "BITS file registration failed.");
            Check(job.Resume(), "BITS job could not be resumed.");

            var deadline = DateTimeOffset.UtcNow.AddHours(1);
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                if (DateTimeOffset.UtcNow >= deadline)
                    throw new InvalidOperationException("BITS update download timed out.");

                Check(job.GetState(out var state), "BITS state could not be read.");
                switch (state)
                {
                    case BackgroundCopyJobState.Transferred:
                        Check(job.Complete(), "BITS job could not be completed.");
                        VerifyDownloadedFile(fullDestination, maxBytes);
                        completed = true;
                        return;
                    case BackgroundCopyJobState.Error:
                    case BackgroundCopyJobState.TransientError:
                    case BackgroundCopyJobState.Cancelled:
                        throw new InvalidOperationException("BITS update download failed.");
                }

                await Task.Delay(PollInterval, ct).ConfigureAwait(false);
            }
        }
        catch (COMException ex)
        {
            throw new InvalidOperationException("Windows BITS is unavailable or could not transfer the update.", ex);
        }
        finally
        {
            if (job is not null)
            {
                try
                {
                    job.GetState(out var state);
                    if (state is not (BackgroundCopyJobState.Transferred or BackgroundCopyJobState.Cancelled))
                        job.Cancel();
                }
                catch (COMException)
                {
                }
            }

            if (!completed)
                TryDelete(fullDestination);
            if (job is not null)
                Marshal.ReleaseComObject(job);
            if (manager is not null)
                Marshal.ReleaseComObject(manager);
        }
    }

    private static void VerifyDownloadedFile(string path, long maxBytes)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length <= 0 || info.Length > maxBytes)
            throw new InvalidOperationException("BITS update artifact length is invalid.");
    }

    private static void Check(int hresult, string message)
    {
        if (hresult < 0)
            Marshal.ThrowExceptionForHR(hresult);
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private enum BackgroundCopyJobType
    {
        Download = 0,
        Upload = 1,
        UploadReply = 2,
    }

    private enum BackgroundCopyJobState
    {
        Queued = 0,
        Connecting = 1,
        Transferring = 2,
        Suspended = 3,
        Error = 4,
        TransientError = 5,
        Transferred = 6,
        Acknowledged = 7,
        Cancelled = 8,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BackgroundCopyJobProgress
    {
        public ulong BytesTotal;
        public ulong BytesTransferred;
        public uint FilesTotal;
        public uint FilesTransferred;
    }

    [ComImport]
    [Guid("4991D34B-80A1-4291-83B6-3328366B9097")]
    private class BackgroundCopyManager
    {
    }

    [ComImport]
    [Guid("5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IBackgroundCopyManager
    {
        [PreserveSig]
        int CreateJob(
            [MarshalAs(UnmanagedType.LPWStr)] string displayName,
            BackgroundCopyJobType type,
            out Guid jobId,
            [MarshalAs(UnmanagedType.Interface)] out IBackgroundCopyJob job);

        [PreserveSig]
        int GetJob(ref Guid jobId, [MarshalAs(UnmanagedType.Interface)] out IBackgroundCopyJob job);

        [PreserveSig]
        int EnumJobs(uint flags, [MarshalAs(UnmanagedType.Interface)] out object jobs);

        [PreserveSig]
        int GetErrorDescription(int errorCode, uint languageId, [MarshalAs(UnmanagedType.LPWStr)] out string description);
    }

    [ComImport]
    [Guid("37668D37-507E-4160-9316-26306D150B12")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IBackgroundCopyJob
    {
        [PreserveSig] int AddFile([MarshalAs(UnmanagedType.LPWStr)] string remoteUrl, [MarshalAs(UnmanagedType.LPWStr)] string localName);
        [PreserveSig] int AddFileSet(uint fileCount, IntPtr fileSet);
        [PreserveSig] int EnumFiles([MarshalAs(UnmanagedType.Interface)] out object files);
        [PreserveSig] int Suspend();
        [PreserveSig] int Resume();
        [PreserveSig] int Cancel();
        [PreserveSig] int Complete();
        [PreserveSig] int GetId(out Guid jobId);
        [PreserveSig] int GetType(out BackgroundCopyJobType type);
        [PreserveSig] int GetProgress(out BackgroundCopyJobProgress progress);
        [PreserveSig] int GetTimes(IntPtr times);
        [PreserveSig] int GetState(out BackgroundCopyJobState state);
        [PreserveSig] int GetError([MarshalAs(UnmanagedType.Interface)] out object error);
        [PreserveSig] int GetOwner(out IntPtr ownerSid);
        [PreserveSig] int SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string displayName);
        [PreserveSig] int GetDisplayName([MarshalAs(UnmanagedType.LPWStr)] out string displayName);
        [PreserveSig] int SetDescription([MarshalAs(UnmanagedType.LPWStr)] string description);
        [PreserveSig] int GetDescription([MarshalAs(UnmanagedType.LPWStr)] out string description);
        [PreserveSig] int SetPriority(uint priority);
        [PreserveSig] int GetPriority(out uint priority);
        [PreserveSig] int SetNotifyFlags(uint flags);
        [PreserveSig] int GetNotifyFlags(out uint flags);
        [PreserveSig] int SetNotifyInterface([MarshalAs(UnmanagedType.Interface)] object callback);
        [PreserveSig] int GetNotifyInterface([MarshalAs(UnmanagedType.Interface)] out object callback);
        [PreserveSig] int SetMinimumRetryDelay(uint seconds);
        [PreserveSig] int GetMinimumRetryDelay(out uint seconds);
        [PreserveSig] int SetNoProgressTimeout(uint seconds);
        [PreserveSig] int GetNoProgressTimeout(out uint seconds);
        [PreserveSig] int GetErrorCount(out uint count);
        [PreserveSig] int SetProxySettings(uint usage, [MarshalAs(UnmanagedType.LPWStr)] string? proxy, [MarshalAs(UnmanagedType.LPWStr)] string? bypass);
        [PreserveSig] int GetProxySettings(out uint usage, [MarshalAs(UnmanagedType.LPWStr)] out string proxy, [MarshalAs(UnmanagedType.LPWStr)] out string bypass);
        [PreserveSig] int TakeOwnership();
    }
}
