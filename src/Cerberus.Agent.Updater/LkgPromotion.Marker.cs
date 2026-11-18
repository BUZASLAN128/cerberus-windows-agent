using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Cerberus.Agent.Core;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Updater;

internal sealed partial class LkgPromotion
{
    internal static AgentUpdateLkgPromotion? ReadMarkerForRecovery(AgentUpdateLkgStore store)
    {
        var path = Path.Combine(store.Root, AgentUpdateLkgStore.PromotionFileName);
        try
        {
            AgentUpdateSecurity.ValidateTrustedPath(path, store.UpdatesRoot, allowMissing: true);
            if (!Exists(path)) return null;
            using var entry = OpenMarkerEntry(path);
            return store.ReadPromotion();
        }
        catch (Exception ex) when (IsPromotionFailure(ex)) { return null; }
    }

    private bool ArchiveMarker(AgentUpdateLkgPromotion? marker, AgentUpdateJournal active,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change)
    {
        try
        {
            Validate(MarkerPath, allowMissing: true);
            if (!Exists(MarkerPath)) return true;
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
