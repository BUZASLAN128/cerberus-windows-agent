using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Cerberus.Agent.Core;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Updater;

internal sealed partial class LkgPromotion
{
    internal enum MarkerState { Absent, Valid, Invalid }

    internal readonly record struct MarkerRead(MarkerState State, AgentUpdateLkgPromotion? Marker = null,
        bool Readable = false);

    internal static bool HasPromotionEntry(AgentUpdateLkgStore store)
    {
        try { return Exists(Path.Combine(store.Root, AgentUpdateLkgStore.PromotionFileName)); }
        catch (Exception ex) when (IsPromotionFailure(ex)) { return true; }
    }

    internal static MarkerRead ReadMarkerForRecovery(AgentUpdateLkgStore store,
        Action<string, string, bool>? validate = null)
    {
        var path = Path.Combine(store.Root, AgentUpdateLkgStore.PromotionFileName);
        try
        {
            (validate ?? AgentUpdateSecurity.ValidateTrustedPath)(path, store.UpdatesRoot, true);
            if (!Exists(path)) return new(MarkerState.Absent);
            using var entry = OpenMarkerEntry(path);
            try
            {
                return store.ReadPromotion() is { } marker
                    ? new(MarkerState.Valid, marker, Readable: true)
                    : new(MarkerState.Invalid, Readable: true);
            }
            catch (Exception ex) when (ex is System.Text.Json.JsonException or InvalidOperationException)
            {
                return new(MarkerState.Invalid, Readable: true);
            }
        }
        catch (Exception ex) when (IsPromotionFailure(ex)) { return new(MarkerState.Invalid); }
    }

    private bool ArchiveMarker(MarkerRead read, AgentUpdateJournal active,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change)
    {
        if (!HasNoAttemptEvidence(store, active.AttemptId, validateProtectedPath)) return false;
        var marker = read.Marker;
        try
        {
            Validate(MarkerPath, allowMissing: true);
            if (read.State == MarkerState.Absent) return !Exists(MarkerPath);
            if (!read.Readable) return false;
            if (marker is not null && OwnsMarker(active, marker)) return false;
            using var source = OpenMarkerEntry(MarkerPath);
            var digest = Hash(source);
            var destination = Path.Combine(store.Root, AgentUpdateLkgStore.StalePromotionPrefix + digest + ".json");
            Validate(destination, allowMissing: true);
            if (MoveFileExW(MarkerPath, destination, 0)) return true;
            var error = Marshal.GetLastWin32Error();
            if (error is not (80 or 183)) throw new Win32Exception(error);

            Validate(destination, allowMissing: false);
            using var existing = OpenMarkerEntry(destination);
            if (Hash(existing) == digest)
            {
                File.Delete(MarkerPath);
                return true;
            }
        }
        catch (Exception ex) when (IsPromotionFailure(ex)) { }

        Alert(change, active, marker?.AttemptId);
        return false;
    }

    private static FileStream OpenMarkerEntry(string path)
    {
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
            throw InvalidPromotion();
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        try
        {
            if (!GetFileInformationByHandleEx(stream.SafeFileHandle, 1, out var info, Marshal.SizeOf<MarkerFileInfo>()))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (info.Links != 1 || info.Directory != 0)
                throw InvalidPromotion();
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MarkerFileInfo
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint Links;
        public byte DeletePending;
        public byte Directory;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileExW(string source, string destination, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, out MarkerFileInfo info, int size);
}
