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
    private const string JobPrefix = "Cerberus.Update.v2:";
    private const string ReceiptFileName = "bits-job.json";
    private sealed record JobReceipt(Guid JobId, string AttemptId);

    public async Task DownloadAsync(
        Uri source,
        string destination,
        long maxBytes,
        CancellationToken ct,
        long? expectedBytes = null)
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
        var attemptDirectory = Path.GetDirectoryName(fullDestination) ?? throw new InvalidOperationException("BITS destination directory is missing.");
        var marker = Path.Combine(attemptDirectory, ".attempt");
        if (!AgentUpdateSecurity.IsLocalSystem() || !File.Exists(marker))
            throw new InvalidOperationException("BITS update authority or attempt is missing.");
        var attemptId = File.ReadAllText(marker);
        if (!AgentUpdateSecurity.IsSafeAttemptId(attemptId) ||
            Path.GetFileName(attemptDirectory) != AgentUpdateSecurity.AttemptDirectoryPrefix + attemptId ||
            Path.GetFileName(fullDestination) != AgentUpdateSecurity.ArtifactFileName + ".part")
            throw new InvalidOperationException("BITS update attempt binding is invalid.");
        AgentUpdateSecurity.ValidateTrustedPath(fullDestination, attemptDirectory, allowMissing: true);
        TryDelete(fullDestination);

        IBackgroundCopyManager? manager = null;
        IBackgroundCopyJob? job = null;
        Guid jobId = default;
        var completed = false;
        try
        {
            manager = (IBackgroundCopyManager)new BackgroundCopyManager();
            Check(manager.CreateJob(
                JobPrefix + attemptId,
                BackgroundCopyJobType.Download,
                out jobId,
                out job), "BITS job creation failed.");
            // BITS creates suspended jobs. Persist its identity before any Resume;
            // a crash before this write leaves an identifiable suspended orphan.
            AgentUpdateDurableFile.Write(Path.Combine(attemptDirectory, ReceiptFileName), attemptDirectory, new JobReceipt(jobId, attemptId));
            Check(job.AddFile(source.AbsoluteUri, fullDestination), "BITS file registration failed.");
            ct.ThrowIfCancellationRequested();
            Check(job.Resume(), "BITS job could not be resumed.");

            var deadline = DateTimeOffset.UtcNow.AddHours(1);
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                if (DateTimeOffset.UtcNow >= deadline)
                    throw new InvalidOperationException("BITS update download timed out.");

                Check(job.GetState(out var state), "BITS state could not be read.");
                Check(job.GetProgress(out var progress), "BITS progress could not be read.");
                if (progress.BytesTransferred > (ulong)maxBytes ||
                    (progress.BytesTotal != ulong.MaxValue && progress.BytesTotal > (ulong)maxBytes))
                    throw new InvalidOperationException("BITS update artifact exceeds size limit.");
                switch (state)
                {
                    case BackgroundCopyJobState.Transferred:
                        Check(job.Complete(), "BITS job could not be completed.");
                        VerifyDownloadedFile(fullDestination, maxBytes);
                        if (expectedBytes is not null && new FileInfo(fullDestination).Length != expectedBytes.Value)
                            throw new InvalidOperationException("BITS update artifact length mismatch.");
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
                    Check(job.GetState(out var state), "BITS final state could not be read.");
                    if (!completed && state is not (BackgroundCopyJobState.Acknowledged or BackgroundCopyJobState.Cancelled))
                        Check(job.Cancel(), "BITS update cancellation failed.");
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

    /// <summary>Cancel only SYSTEM-owned update jobs bound to this protected attempt tree; prove quiescence with a second enumeration.</summary>
    public static void Quiesce(string root)
    {
        if (!OperatingSystem.IsWindows() || !AgentUpdateSecurity.IsLocalSystem())
            throw new InvalidOperationException("BITS reconciliation requires the installed SYSTEM service.");
        AgentUpdateSecurity.EnsureProtectedRoot(root);
        IBackgroundCopyManager? manager = null;
        try
        {
            manager = (IBackgroundCopyManager)new BackgroundCopyManager();
            VisitOwnedJobs(manager, root, job => Check(job.Cancel(), "BITS retirement failed."));
            VisitOwnedJobs(manager, root, job =>
            {
                Check(job.GetState(out var state), "BITS retirement state is unavailable.");
                if (state is not (BackgroundCopyJobState.Cancelled or BackgroundCopyJobState.Acknowledged))
                    throw new InvalidOperationException("BITS retirement is incomplete.");
            });
        }
        finally
        {
            if (manager is not null)
                Marshal.ReleaseComObject(manager);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void VisitOwnedJobs(IBackgroundCopyManager manager, string root, Action<IBackgroundCopyJob> visit)
    {
        Check(manager.EnumJobs(0, out var rawJobs), "BITS enumeration failed.");
        var jobs = (IEnumBackgroundCopyJobs)rawJobs;
        try
        {
            Check(jobs.GetCount(out var count), "BITS enumeration count failed.");
            if (count > 4096)
                throw new InvalidOperationException("BITS job inventory exceeds reconciliation bounds.");
            for (uint index = 0; index < count; index++)
            {
                Check(jobs.Next(1, out var job, out var fetched), "BITS enumeration failed.");
                if (fetched == 0)
                    break;
                try
                {
                    Check(job.GetDisplayName(out var name), "BITS ownership could not be read.");
                    var legacy = name == "Cerberus Agent update";
                    if (!legacy && !name.StartsWith(JobPrefix, StringComparison.Ordinal))
                        continue;
                    Check(job.GetOwner(out var owner), "BITS ownership could not be read.");
                    if (owner != "S-1-5-18")
                        continue;
                    var attemptId = legacy ? ReadLegacyAttemptId(job, root) : name[JobPrefix.Length..];
                    var directory = AgentUpdateSecurity.ResolveAttemptDirectory(root, attemptId);
                    if (File.ReadAllText(Path.Combine(directory, ".attempt")) != attemptId)
                        throw new InvalidOperationException("BITS attempt marker mismatch.");
                    var receipt = AgentUpdateDurableFile.Read<JobReceipt>(Path.Combine(directory, ReceiptFileName), directory);
                    if (receipt is not null && receipt.AttemptId != attemptId)
                        throw new InvalidOperationException("BITS job receipt binding mismatch.");
                    Check(job.GetId(out var jobId), "BITS job identity is unavailable.");
                    // A different GUID is an orphan from suspended creation; the protected
                    // attempt marker and destination still bind it to this updater owner.
                    VerifyOwnedFiles(job, directory);
                    visit(job);
                }
                finally
                {
                    Marshal.ReleaseComObject(job);
                }
            }
        }
        finally
        {
            Marshal.ReleaseComObject(jobs);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string ReadLegacyAttemptId(IBackgroundCopyJob job, string root)
    {
        Check(job.EnumFiles(out var raw), "Legacy BITS inventory is unavailable.");
        var files = (IEnumBackgroundCopyFiles)raw;
        try
        {
            Check(files.GetCount(out var count), "Legacy BITS inventory is unavailable.");
            if (count != 1) throw new InvalidOperationException("Legacy BITS ownership requires manual recovery.");
            Check(files.Next(1, out var file, out var fetched), "Legacy BITS inventory is unavailable.");
            if (fetched != 1) throw new InvalidOperationException("Legacy BITS ownership requires manual recovery.");
            try
            {
                Check(file.GetLocalName(out var path), "Legacy BITS destination is unavailable.");
                AgentUpdateSecurity.ValidateTrustedPath(path, Path.Combine(root, "attempts"), allowMissing: true);
                var name = Path.GetFileName(Path.GetDirectoryName(path));
                if (name is null || !name.StartsWith(AgentUpdateSecurity.AttemptDirectoryPrefix, StringComparison.Ordinal))
                    throw new InvalidOperationException("Legacy BITS ownership requires manual recovery.");
                return name[AgentUpdateSecurity.AttemptDirectoryPrefix.Length..];
            }
            finally { Marshal.ReleaseComObject(file); }
        }
        finally { Marshal.ReleaseComObject(files); }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void VerifyOwnedFiles(IBackgroundCopyJob job, string directory)
    {
        Check(job.EnumFiles(out var rawFiles), "BITS file enumeration failed.");
        var files = (IEnumBackgroundCopyFiles)rawFiles;
        try
        {
            Check(files.GetCount(out var count), "BITS file count failed.");
            if (count > 1)
                throw new InvalidOperationException("BITS attempt contains unexpected files.");
            if (count == 0)
                return; // Crash between suspended CreateJob and AddFile.
            Check(files.Next(1, out var file, out var fetched), "BITS file enumeration failed.");
            if (fetched != 1)
                throw new InvalidOperationException("BITS file ownership is unavailable.");
            try
            {
                Check(file.GetLocalName(out var local), "BITS destination is unavailable.");
                var expected = Path.Combine(directory, AgentUpdateSecurity.ArtifactFileName + ".part");
                if (!string.Equals(Path.GetFullPath(local), expected, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("BITS destination does not belong to this attempt.");
                AgentUpdateSecurity.ValidateTrustedPath(local, directory, allowMissing: true);
            }
            finally { Marshal.ReleaseComObject(file); }
        }
        finally { Marshal.ReleaseComObject(files); }
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
        // COM vtable order is the Bits.h ABI, not alphabetical order. AddFileSet is slot 3; AddFile is slot 4.
        [PreserveSig] int AddFileSet(uint fileCount, IntPtr fileSet);
        [PreserveSig] int AddFile([MarshalAs(UnmanagedType.LPWStr)] string remoteUrl, [MarshalAs(UnmanagedType.LPWStr)] string localName);
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
        [PreserveSig] int GetOwner([MarshalAs(UnmanagedType.LPWStr)] out string ownerSid);
        [PreserveSig] int SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string displayName);
        [PreserveSig] int GetDisplayName([MarshalAs(UnmanagedType.LPWStr)] out string displayName);
        [PreserveSig] int SetDescription([MarshalAs(UnmanagedType.LPWStr)] string description);
        [PreserveSig] int GetDescription([MarshalAs(UnmanagedType.LPWStr)] out string description);
        [PreserveSig] int SetPriority(uint priority);
        [PreserveSig] int GetPriority(out uint priority);
        [PreserveSig] int SetNotifyFlags(uint flags);
        [PreserveSig] int GetNotifyFlags(out uint flags);
        [PreserveSig] int SetNotifyInterface([MarshalAs(UnmanagedType.IUnknown)] object callback);
        [PreserveSig] int GetNotifyInterface([MarshalAs(UnmanagedType.IUnknown)] out object callback);
        [PreserveSig] int SetMinimumRetryDelay(uint seconds);
        [PreserveSig] int GetMinimumRetryDelay(out uint seconds);
        [PreserveSig] int SetNoProgressTimeout(uint seconds);
        [PreserveSig] int GetNoProgressTimeout(out uint seconds);
        [PreserveSig] int GetErrorCount(out uint count);
        [PreserveSig] int SetProxySettings(uint usage, [MarshalAs(UnmanagedType.LPWStr)] string? proxy, [MarshalAs(UnmanagedType.LPWStr)] string? bypass);
        [PreserveSig] int GetProxySettings(out uint usage, [MarshalAs(UnmanagedType.LPWStr)] out string proxy, [MarshalAs(UnmanagedType.LPWStr)] out string bypass);
        [PreserveSig] int TakeOwnership();
    }

    [ComImport, Guid("1AF4F612-3B71-466F-8F58-7B6F73AC57AD"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IEnumBackgroundCopyJobs
    {
        [PreserveSig] int Next(uint count, [MarshalAs(UnmanagedType.Interface)] out IBackgroundCopyJob job, out uint fetched);
        [PreserveSig] int Skip(uint count);
        [PreserveSig] int Reset();
        [PreserveSig] int Clone([MarshalAs(UnmanagedType.Interface)] out IEnumBackgroundCopyJobs clone);
        [PreserveSig] int GetCount(out uint count);
    }

    [ComImport, Guid("CA51E165-C365-424C-8D41-24AAA4FF3C40"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IEnumBackgroundCopyFiles
    {
        [PreserveSig] int Next(uint count, [MarshalAs(UnmanagedType.Interface)] out IBackgroundCopyFile file, out uint fetched);
        [PreserveSig] int Skip(uint count);
        [PreserveSig] int Reset();
        [PreserveSig] int Clone([MarshalAs(UnmanagedType.Interface)] out IEnumBackgroundCopyFiles clone);
        [PreserveSig] int GetCount(out uint count);
    }

    [ComImport, Guid("01B7BD23-FB88-4A77-8490-5891D3E4653A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IBackgroundCopyFile
    {
        [PreserveSig] int GetRemoteName([MarshalAs(UnmanagedType.LPWStr)] out string name);
        [PreserveSig] int GetLocalName([MarshalAs(UnmanagedType.LPWStr)] out string name);
        [PreserveSig] int GetProgress(IntPtr progress);
    }
}
