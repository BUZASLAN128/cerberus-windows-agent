using System.ComponentModel;
using System.Security.AccessControl;
using System.Security.Principal;
using Cerberus.Agent.Core;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Core.Tests;

internal sealed class StoppedRemovalFixture(Action<string, object> trace)
{
    private const string RootPrefix = "cerberus-stopped-cache-";
    private readonly List<Node> _nodes = [];
    private readonly List<SafeFileHandle> _tempAnchors = [];
    private Node? _root;

    internal sealed class Node(string path, string sddl, bool directory, Node? parent)
    {
        internal string Path { get; } = path;
        internal string Sddl { get; } = sddl;
        internal bool Directory { get; } = directory;
        internal Node? Parent { get; } = parent;
        internal long? Id { get; set; }
        internal bool Removed { get; set; }
    }

    internal Node Start()
    {
        var temp = Path.TrimEndingDirectorySeparator(Path.GetFullPath(Path.GetTempPath()));
        var drive = Path.GetPathRoot(temp);
        if (drive is null || drive.Length != 3 || drive[1] != ':' || temp == drive ||
            new DriveInfo(drive) is not { DriveType: DriveType.Fixed, DriveFormat: "NTFS" })
            throw new InvalidOperationException("A local fixed NTFS Temp root is required.");

        var commonData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData,
            Environment.SpecialFolderOption.DoNotVerify);
        if (!Path.IsPathFullyQualified(commonData) || Inside(temp, Path.GetFullPath(commonData)))
            throw new InvalidOperationException("The requested Temp location intersects ProgramData.");
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows, Environment.SpecialFolderOption.DoNotVerify);
        if (Inside(temp, windir) &&
            !new[] { Path.Combine(windir, "Temp"), Path.Combine(windir, "SystemTemp") }.Any(location => Inside(temp, location)))
            throw new InvalidOperationException("Windows-system Temp is limited to the known Temp directories.");

        // Pin every exact Temp ancestor without delete sharing before creating anything.
        var current = drive;
        Hold(current);
        foreach (var part in temp[drive.Length..].Split(Path.DirectorySeparatorChar))
        {
            current = Path.Combine(current, part);
            Hold(current);
        }

        using var actor = WindowsIdentity.GetCurrent();
        var sid = actor.User?.Value ?? throw new InvalidOperationException("The actor SID is unavailable.");
        var root = Path.Combine(temp, RootPrefix + Guid.NewGuid().ToString("N"));
        trace("scope", new { temp, root, outsideProgramData = true, ntfs = true, ancestorCount = _tempAnchors.Count });
        _root = Create(root, $"O:{sid}D:P(A;;FA;;;{sid})", true, null);
        return _root;

        void Hold(string ancestor)
        {
            var handle = StoppedRemovalNativeFile.RequireOpen(ancestor, StoppedRemovalNativeFile.ReadAttributes);
            _tempAnchors.Add(handle);
            CheckShape(handle, ancestor, directory: true);
        }
    }

    internal Node Directory(Node parent, string name, string sddl)
        => Add(parent, name, sddl, directory: true);

    internal Node File(Node parent, string name, string sddl, byte[]? contents = null)
        => Add(parent, name, sddl, directory: false, contents);

    private Node Add(Node parent, string name, string sddl, bool directory, byte[]? contents = null)
    {
        if (name.Length == 0 || name.Any(ch => !(char.IsAsciiLetterOrDigit(ch) || ch is '-' or '.')) ||
            name is "." or ".." || name.EndsWith('.'))
            throw new InvalidOperationException("Fixture entries require exact, simple names.");
        if (!parent.Directory || parent.Id is null || parent.Removed || !_nodes.Contains(parent))
            throw new InvalidOperationException("Fixture parent is not a bound directory.");
        return Create(Path.Combine(parent.Path, name), sddl, directory, parent, contents);
    }

    private Node Create(string path, string sddl, bool directory, Node? parent, byte[]? contents = null)
    {
        var node = new Node(path, sddl, directory, parent);
        AgentUpdateStoragePrivilege.Run(() =>
        {
            using var parentHandle = parent is null ? null : OpenChecked(parent, StoppedRemovalNativeFile.ReadControl);
            if (directory)
            {
                StoppedRemovalNativeFile.CreateDirectory(path, sddl);
                _nodes.Add(node);
                using var handle = StoppedRemovalNativeFile.RequireOpen(path, StoppedRemovalNativeFile.ReadControl);
                Bind(node, handle);
            }
            else
            {
                using var handle = StoppedRemovalNativeFile.CreateRegular(path, sddl);
                _nodes.Add(node);
                Bind(node, handle);
                if (contents is not null)
                {
                    using var stream = new FileStream(handle, FileAccess.Write);
                    stream.Write(contents);
                    stream.Flush(flushToDisk: true);
                }
            }
        });
        return node;
    }

    private void Bind(Node node, SafeFileHandle handle)
    {
        CheckShape(handle, node.Path, node.Directory);
        var sddl = StoppedRemovalNativeFile.Descriptor(handle);
        if (!SameDescriptor(node.Sddl, sddl))
            throw new InvalidOperationException("Fixture object has an unexpected owner or DACL.");
        var (status, id) = StoppedRemovalNativeFile.ReadId(handle);
        if (status != 0) throw new InvalidOperationException($"Cannot bind fixture file ID. NTSTATUS 0x{status:X8}.");
        node.Id = id;
        trace("created", new { node.Path, node.Directory, id, sddl });
    }

    internal SafeFileHandle OpenChecked(Node node, uint mask)
        => VerifyOpened(node, StoppedRemovalNativeFile.RequireOpen(node.Path, mask));

    internal SafeFileHandle HoldCacheDirectory(Node node)
    {
        if (!node.Directory || node.Id is null || node.Removed || !_nodes.Contains(node))
            throw new InvalidOperationException("Cache custody requires a bound fixture directory.");

        // The admin ACE grants READ_CONTROL only. Use a private backup token for the
        // synchronous metadata open and checks. Only the pinned handle survives this scope.
        SafeFileHandle? handle = null;
        try
        {
            StoppedRemovalToken.RunAndVerifyBackupOnly(() =>
                handle = VerifyOpened(node, StoppedRemovalNativeFile.OpenCacheDirectoryMetadata(node.Path)));
            return handle!;
        }
        catch
        {
            handle?.Dispose();
            throw;
        }
    }

    private static SafeFileHandle VerifyOpened(Node node, SafeFileHandle handle)
    {
        try
        {
            CheckShape(handle, node.Path, node.Directory);
            var sddl = StoppedRemovalNativeFile.Descriptor(handle);
            var (status, id) = StoppedRemovalNativeFile.ReadId(handle);
            if (status != 0 || id != node.Id || !SameDescriptor(node.Sddl, sddl))
                throw new InvalidOperationException("Fixture identity, owner or DACL changed.");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    // Read absence through the same narrow open used for disposal. Access denial is an error.
    internal void ObservePresence(Node node)
    {
        using var handle = OpenDisposition(node);
        trace("presence", new { node.Path, present = handle is not null });
    }

    private SafeFileHandle? OpenDisposition(Node node)
    {
        if (node.Id is null || node.Parent is { Removed: true })
            throw new InvalidOperationException("Fixture setup did not bind the exact object and its parent.");
        var (handle, error) = StoppedRemovalNativeFile.OpenForDisposition(node.Path, node.Directory);
        if (error == 2)
        {
            handle.Dispose();
            node.Removed = true;
            trace("absence", new { node.Path, win32 = error });
            return null;
        }
        try
        {
            if (error != 0)
                throw new Win32Exception(error);
            if (handle.IsInvalid)
                throw new InvalidOperationException("Fixture entry handle is invalid.");
            CheckShape(handle, node.Path, node.Directory);
            var (status, id) = StoppedRemovalNativeFile.ReadId(handle);
            if (status != 0 || id != node.Id)
                throw new InvalidOperationException("Fixture identity changed.");
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal void Cleanup()
    {
        try
        {
            AgentUpdateStoragePrivilege.Run(() =>
            {
                var openings = new List<(Node Node, SafeFileHandle Handle)>();
                try
                {
                    // Qualify every remaining entry before sending any disposition. Keep all handles
                    // open so a name cannot be substituted between qualification and removal.
                    foreach (var node in _nodes.Where(node => !node.Removed))
                    {
                        if (OpenDisposition(node) is { } handle) openings.Add((node, handle));
                    }
                    foreach (var (node, handle) in openings.AsEnumerable().Reverse())
                    {
                        var (success, win32) = StoppedRemovalNativeFile.Disposition(handle);
                        trace("teardown-disposition", new { node.Path, success, win32 });
                        if (!success) throw new Win32Exception(win32);
                        handle.Dispose();
                        using var stillPresent = OpenDisposition(node);
                        if (stillPresent is not null) throw new InvalidOperationException("An exact fixture entry survived disposal.");
                    }
                    trace("teardown", new { root = _root?.Path, terminal = "exact entries absent" });
                }
                finally
                {
                    foreach (var (_, handle) in openings) handle.Dispose();
                }
            });
        }
        finally
        {
            foreach (var handle in _tempAnchors.AsEnumerable().Reverse()) handle.Dispose();
        }
    }

    internal static void CheckShape(SafeFileHandle handle, string path, bool directory)
    {
        if (!string.Equals(StoppedRemovalNativeFile.OpenedPath(handle), @"\\?\" + path, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Handle pathname diverges from the fixture path.");
        var reparse = StoppedRemovalNativeFile.Reparse(handle);
        if (reparse.Success || reparse.Win32 != StoppedRemovalNativeFile.NotAReparsePoint)
            throw new InvalidOperationException($"Fixture shape reparse check failed. Win32 {reparse.Win32}.");
        var standard = StoppedRemovalNativeFile.Standard(handle);
        if (!standard.Success || (standard.Info.Directory != 0) != directory ||
            standard.Info.DeletePending != 0 || (!directory && standard.Info.LinkCount != 1))
            throw new InvalidOperationException($"Fixture shape standard-info check failed. Win32 {standard.Win32}.");
    }

    private static bool Inside(string path, string parent)
    {
        if (string.IsNullOrEmpty(parent)) return false;
        parent = Path.TrimEndingDirectorySeparator(parent);
        return path.Equals(parent, StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static bool SameDescriptor(string expectedSddl, string actualSddl)
    {
        var expected = new RawSecurityDescriptor(expectedSddl);
        var actual = new RawSecurityDescriptor(actualSddl);
        if (expected.Owner != actual.Owner || !actual.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected) ||
            expected.DiscretionaryAcl is not { } expectedAcl || actual.DiscretionaryAcl is not { } actualAcl)
            return false;
        var expectedBytes = new byte[expectedAcl.BinaryLength];
        var actualBytes = new byte[actualAcl.BinaryLength];
        expectedAcl.GetBinaryForm(expectedBytes, 0);
        actualAcl.GetBinaryForm(actualBytes, 0);
        return expectedBytes.AsSpan().SequenceEqual(actualBytes);
    }
}
