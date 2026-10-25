using System.ComponentModel;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Cerberus.Agent.Core;

/// <summary>
/// Provenance gate and writer for machine-state files (signed agent state, command replay store).
/// A path under <c>&lt;DataDir&gt;\Privileged</c> is a machine path: its ancestors, owner and DACL must be
/// SYSTEM/Administrators (<see cref="AgentUpdateSecurity"/>), new files are created with a SYSTEM and
/// Administrators-only DACL, and a missing directory is created only by LocalSystem. Any other path keeps
/// plain file semantics, plus the file-level checks when <c>enforceFileProvenance</c> is set.
/// A directory or reparse point at the file path is always refused.
/// </summary>
internal sealed class ProtectedMachineFile
{
    private readonly string _path;
    private readonly string _directory;
    private readonly bool _machine;
    private readonly bool _enforceFile;

    public ProtectedMachineFile(string path, bool enforceFileProvenance = false)
    {
        _path = Path.GetFullPath(path);
        _directory = Path.GetDirectoryName(_path) ?? throw new ArgumentException("Path needs a directory.", nameof(path));
        _machine = AgentUpdateSecurity.IsUnderDirectory(_path, PrivilegedRoot);
        _enforceFile = _machine || enforceFileProvenance;
    }

    public static string PrivilegedRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        AgentInstallIdentity.DataDirName,
        AgentUpdateSecurity.PrivilegedDirectoryName);

    public static string DefaultPath(string fileName) => Path.Combine(PrivilegedRoot, fileName);

    /// <summary>I/O, permission and provenance failures; every one of them fails the store closed.</summary>
    public static bool IsFailure(Exception ex)
        => ex is IOException or UnauthorizedAccessException or InvalidOperationException or NotSupportedException
            or Win32Exception or SecurityException;

    /// <summary>Something occupies the path (file, directory or link). An unreadable path counts as present.</summary>
    public bool Exists()
    {
        try
        {
            _ = File.GetAttributes(_path);
            return true;
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return false;
        }
        catch (Exception ex) when (IsFailure(ex))
        {
            return true;
        }
    }

    /// <summary>Machine paths: the product root and <c>Privileged</c> must be trusted. A missing directory passes.</summary>
    public void ValidateDirectory()
    {
        if (_machine)
            AgentUpdateSecurity.ValidateProtectedPath(_directory, _directory, allowMissing: true);
    }

    /// <summary>Throws unless the existing object at the path is a regular file with trusted provenance.</summary>
    public void ValidateFile()
    {
        var attributes = File.GetAttributes(_path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Machine state path is a reparse point.");
        if ((attributes & FileAttributes.Directory) != 0)
            throw new InvalidOperationException("Machine state path is a directory.");
        if (!_enforceFile || !OperatingSystem.IsWindows())
            return;

        if (_machine)
        {
            AgentUpdateSecurity.ValidateProtectedPath(_path, _directory, allowMissing: false);
            return;
        }

        var security = new FileInfo(_path).GetAccessControl();
        AgentUpdateSecurity.ValidateDescriptor(new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0));
    }

    /// <summary>Validates the directory chain and creates the directory when it is missing.</summary>
    public void EnsureDirectory()
    {
        if (!_machine)
        {
            Directory.CreateDirectory(_directory);
            return;
        }

        ValidateDirectory();
        if (Directory.Exists(_directory))
            return;
        if (!AgentUpdateSecurity.IsLocalSystem())
            throw new UnauthorizedAccessException("Only the agent service can create machine state storage.");
        AgentUpdateSecurity.EnsureProtectedRoot(_directory);
    }

    /// <summary>A new exclusive temp file next to the target; machine files get a SYSTEM/Administrators-only DACL at creation.</summary>
    public FileStream CreateTemp(string tempPath)
        => _machine && OperatingSystem.IsWindows()
            ? CreateProtected(tempPath)
            : new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);

    [SupportedOSPlatform("windows")]
    private static FileStream CreateProtected(string tempPath)
    {
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var acl = new FileSecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(AgentUpdateSecurity.IsLocalSystem() ? system : administrators);
        acl.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(administrators, FileSystemRights.FullControl, AccessControlType.Allow));
        // The DACL is applied at creation, so no standard user can open even the empty temp file.
        return new FileInfo(tempPath).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096,
            FileOptions.WriteThrough, acl);
    }
}
