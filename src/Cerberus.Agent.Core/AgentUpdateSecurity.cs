using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Cerberus.Agent.Core;

/// <summary>
/// File-system and process-authority invariants for the privileged update area.
/// </summary>
public static class AgentUpdateSecurity
{
    public const string PrivilegedDirectoryName = "Privileged";
    public const string UpdatesDirectoryName = "Updates";
    public const string AttemptDirectoryPrefix = "attempt-";
    public const string PlanFileName = "update-plan.json";
    public const string ManifestFileName = "manifest.json";
    public const string ArtifactFileName = "agent.msi";
    public const string GlobalLockFileName = "update.lock";
    // SDDL "DC" is the directory-services bit 0x2 (FILE_ADD_FILE on a filesystem), not FILE_DELETE_CHILD.
    internal const string ProductDirectorySddl = "O:SYG:SYD:P(D;;0x40;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;GRGWGX;;;BU)(A;OI;GRGWGX;;;BU)";

    public static string DefaultPrivilegedRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CerberusAgent",
        PrivilegedDirectoryName,
        UpdatesDirectoryName);

    public static bool IsLocalSystem()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem;
    }

    public static bool IsSafeAttemptId(string? attemptId)
        => !string.IsNullOrWhiteSpace(attemptId) &&
           attemptId.Length <= 64 &&
           attemptId.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_');

    public static string NormalizeRoot(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Privileged update root is required.", nameof(root));

        var fullPath = Path.GetFullPath(root.Trim());
        var fileSystemRoot = Path.GetPathRoot(fullPath);
        return string.Equals(fullPath, fileSystemRoot, StringComparison.OrdinalIgnoreCase)
            ? fullPath
            : fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    /// <summary>Creates missing authority atomically. Existing objects must already have trusted provenance; none are repaired into trust.</summary>
    public static void EnsureProtectedRoot(string root)
    {
        var fullRoot = NormalizeRoot(root);
        ValidateExistingAncestors(fullRoot);
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(fullRoot);
            return;
        }

        // Validate before even enabling the ownership privilege. Parent ACL changes cannot bless preseeded children.
        var targets = GetProtectionTargets(fullRoot).ToArray();
        foreach (var directory in targets)
        {
            if (Directory.Exists(directory))
                ValidateDirectoryAuthority(directory, isProductRoot: IsProductRoot(directory));
        }
        var namespaceRoot = IsUnderDirectory(fullRoot, DefaultPrivilegedNamespaceRoot) ? DefaultPrivilegedNamespaceRoot : fullRoot;
        if (Directory.Exists(namespaceRoot))
            ValidateProtectedTree(namespaceRoot);

        var missing = targets.Where(directory => !Directory.Exists(directory)).ToArray();
        if (missing.Length == 0) return;
        AgentUpdateStoragePrivilege.Run(() =>
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            foreach (var directory in targets)
            {
                ValidateExistingAncestors(directory);
                if (!Directory.Exists(directory))
                    CreateProtectedDirectory(directory, IsProductRoot(directory));
                // CreateDirectory may lose a race to an existing object. Never adopt it on name alone.
                ValidateDirectoryAuthority(directory, IsProductRoot(directory));
            }
        });
        ValidateProtectedTree(namespaceRoot);
    }

    /// <summary>Read-only provenance gate for a protected directory or record. Stronger SYSTEM-only lifecycle ACLs are accepted.</summary>
    public static void ValidateProtectedPath(string path, string trustedRoot, bool allowMissing)
    {
        ValidatePathShape(path, trustedRoot, allowMissing);
        if (!OperatingSystem.IsWindows()) return;
        var fullRoot = NormalizeRoot(trustedRoot);
        var fullPath = Path.GetFullPath(path);
        var anchor = IsUnderDirectory(fullRoot, DefaultPrivilegedNamespaceRoot) ? DefaultPrivilegedNamespaceRoot : fullRoot;
        if (IsUnderDirectory(fullRoot, DefaultPrivilegedNamespaceRoot))
        {
            if (Directory.Exists(DefaultProductRoot)) ValidateDirectoryAuthority(DefaultProductRoot, isProductRoot: true);
        }
        ValidateProtectedComponents(anchor, fullPath, allowMissing, allowTrustedInstaller: false);
    }

    /// <summary>Refuses every preexisting unsafe descendant without modifying or deleting it.</summary>
    public static void ValidateProtectedTree(string root)
    {
        ValidateProtectedPath(root, root, allowMissing: false);
        if (!OperatingSystem.IsWindows()) return;
        var pending = new Stack<string>();
        pending.Push(NormalizeRoot(root));
        var count = 0;
        while (pending.TryPop(out var directory))
        {
            foreach (var path in Directory.EnumerateFileSystemEntries(directory))
            {
                if (++count > 65536) throw new InvalidOperationException("Protected update inventory exceeds validation bounds.");
                ValidateNoReparsePoint(path, "Protected update descendant");
                ValidateObjectAuthority(path, allowTrustedInstaller: false, isProductRoot: false);
                if (Directory.Exists(path)) pending.Push(path);
            }
        }
    }

    internal static void ValidateInstalledSource(string path, string runtimeDirectory)
    {
        ValidatePathShape(path, runtimeDirectory, allowMissing: false);
        if (!OperatingSystem.IsWindows()) return;
        // The installed source, not a colocated inventory, establishes runner code provenance.
        ValidateProtectedComponents(NormalizeRoot(runtimeDirectory), Path.GetFullPath(path), allowMissing: false, allowTrustedInstaller: true);
        var parent = Directory.GetParent(NormalizeRoot(runtimeDirectory));
        while (parent is not null)
        {
            ValidateNoReparsePoint(parent.FullName, "Installed update source ancestor");
            ValidateObjectAuthority(parent.FullName, allowTrustedInstaller: true, isProductRoot: true);
            parent = parent.Parent;
        }
    }

    public static FileStream AcquireGlobalLock(string root)
    {
        var fullRoot = NormalizeRoot(root);
        EnsureProtectedRoot(fullRoot);
        var path = Path.Combine(fullRoot, GlobalLockFileName);
        ValidateTrustedPath(path, fullRoot, allowMissing: true);
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    public static string CreateExclusiveAttemptDirectory(string root, string attemptId)
    {
        var fullRoot = NormalizeRoot(root);
        if (!IsSafeAttemptId(attemptId))
            throw new InvalidOperationException("Update attempt identifier is invalid.");

        EnsureProtectedRoot(fullRoot);
        var versionRoot = Path.Combine(fullRoot, "attempts");
        Directory.CreateDirectory(versionRoot);
        ValidateTrustedPath(versionRoot, fullRoot, allowMissing: false);

        var attemptPath = Path.Combine(versionRoot, AttemptDirectoryPrefix + attemptId);
        try
        {
            Directory.CreateDirectory(attemptPath);
        }
        catch (IOException ex)
        {
            throw new InvalidOperationException("Update attempt could not be created exclusively.", ex);
        }

        ValidateTrustedPath(attemptPath, versionRoot, allowMissing: false);
        var marker = Path.Combine(attemptPath, ".attempt");
        ValidateTrustedPath(marker, fullRoot, allowMissing: true);
        try
        {
            using var stream = new FileStream(marker, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var writer = new StreamWriter(stream);
            writer.Write(attemptId);
            writer.Flush();
        }
        catch (IOException ex)
        {
            throw new InvalidOperationException("Update attempt already exists.", ex);
        }

        ValidateTrustedPath(marker, fullRoot, allowMissing: false);

        return attemptPath;
    }

    public static string ResolveAttemptDirectory(string root, string attemptId)
    {
        var fullRoot = NormalizeRoot(root);
        if (!IsSafeAttemptId(attemptId))
            throw new InvalidOperationException("Update attempt identifier is invalid.");

        var attemptsRoot = Path.Combine(fullRoot, "attempts");
        var attemptPath = Path.Combine(attemptsRoot, AttemptDirectoryPrefix + attemptId);
        ValidateTrustedPath(attemptPath, attemptsRoot, allowMissing: false);
        return attemptPath;
    }

    public static void ValidateTrustedPath(string path, string trustedRoot, bool allowMissing)
    {
        ValidatePathShape(path, trustedRoot, allowMissing);
        // Non-machine roots are retained for pure serializer/support tests. All production machine records
        // are fenced here regardless of which nested directory a caller supplies as trustedRoot.
        if (IsUnderDirectory(Path.GetFullPath(path), DefaultPrivilegedNamespaceRoot))
            ValidateProtectedPath(path, trustedRoot, allowMissing);
    }

    private static void ValidatePathShape(string path, string trustedRoot, bool allowMissing)
    {
        var fullRoot = NormalizeRoot(trustedRoot);
        var fullPath = Path.GetFullPath(path);
        if (!IsUnderDirectory(fullPath, fullRoot))
            throw new InvalidOperationException("Update path is outside protected storage.");
        ValidateExistingAncestors(fullPath);
        if (!allowMissing && !File.Exists(fullPath) && !Directory.Exists(fullPath))
            throw new FileNotFoundException("Protected update item was not found.");
    }

    public static bool IsUnderDirectory(string path, string directory)
    {
        var fullPath = Path.GetFullPath(path);
        var fullDirectory = NormalizeRoot(directory);
        return string.Equals(fullPath, fullDirectory, StringComparison.OrdinalIgnoreCase) ||
               fullPath.StartsWith(Path.EndsInDirectorySeparator(fullDirectory) ? fullDirectory : fullDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string DefaultProductRoot => Path.Combine(
        NormalizeRoot(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)), "CerberusAgent");
    private static string DefaultPrivilegedNamespaceRoot => Path.Combine(DefaultProductRoot, PrivilegedDirectoryName);
    private static bool IsProductRoot(string path) => string.Equals(NormalizeRoot(path), DefaultProductRoot, StringComparison.OrdinalIgnoreCase);

    private static IEnumerable<string> GetProtectionTargets(string fullRoot)
    {
        if (!IsUnderDirectory(fullRoot, DefaultPrivilegedNamespaceRoot)) return new[] { fullRoot };
        var targets = new List<string> { DefaultProductRoot, DefaultPrivilegedNamespaceRoot };
        var relative = Path.GetRelativePath(DefaultPrivilegedNamespaceRoot, fullRoot);
        var current = DefaultPrivilegedNamespaceRoot;
        if (relative != ".")
            foreach (var component in relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            {
                current = Path.Combine(current, component);
                targets.Add(current);
            }
        return targets;
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateProtectedComponents(string root, string path, bool allowMissing, bool allowTrustedInstaller)
    {
        var current = NormalizeRoot(root);
        var components = Path.GetRelativePath(current, path);
        var paths = new List<string> { current };
        if (components != ".")
            foreach (var component in components.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            {
                current = Path.Combine(current, component);
                paths.Add(current);
            }
        foreach (var candidate in paths)
        {
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                if (allowMissing) return;
                throw new FileNotFoundException("Protected update item was not found.");
            }
            ValidateNoReparsePoint(candidate, "Protected update item");
            // The canonical product container also hosts guarded active-machine ciphertext outside Privileged.
            // Its namespace-only grants are not permissions for any child record or arbitrary ancestor.
            ValidateObjectAuthority(candidate, allowTrustedInstaller, isProductRoot: IsProductRoot(candidate));
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateDirectoryAuthority(string directory, bool isProductRoot)
    {
        ValidateNoReparsePoint(directory, "Protected update directory");
        ValidateObjectAuthority(directory, allowTrustedInstaller: false, isProductRoot);
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateObjectAuthority(string path, bool allowTrustedInstaller, bool isProductRoot)
    {
        var result = GetNamedSecurityInfo(path, SeObjectTypeFile, OwnerSecurityInformation | DaclSecurityInformation,
            out _, out _, out _, out _, out var descriptor);
        if (result != ErrorSuccess) throw new InvalidOperationException("Protected update provenance is unavailable.", new Win32Exception((int)result));
        try
        {
            var length = GetSecurityDescriptorLength(descriptor);
            if (length is 0 or > 65536) throw new InvalidOperationException("Protected update provenance is invalid.");
            var bytes = new byte[length];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            ValidateDescriptor(new RawSecurityDescriptor(bytes, 0), allowTrustedInstaller, isProductRoot);
        }
        finally { _ = LocalFree(descriptor); }
    }

    [SupportedOSPlatform("windows")]
    internal static void ValidateDescriptor(RawSecurityDescriptor descriptor, bool allowTrustedInstaller = false, bool isProductRoot = false)
    {
        static bool Trusted(SecurityIdentifier? sid, bool allowInstaller) => sid?.Value is "S-1-5-18" or "S-1-5-32-544" ||
            (allowInstaller && sid?.Value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
        if (!Trusted(descriptor.Owner, allowTrustedInstaller) || descriptor.DiscretionaryAcl is null ||
            (descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
            throw new InvalidOperationException("Protected update object has untrusted ownership or permissions.");
        // Parent namespaces may allow unrelated file creation, but never replacement/rename of protected children.
        var forbidden = isProductRoot ? 0x100D0040u : 0x500D0156u;
        foreach (GenericAce ace in descriptor.DiscretionaryAcl)
        {
            if (ace is not QualifiedAce qualified)
                throw new InvalidOperationException("Protected update object has unsupported permissions.");
            if (qualified.AceQualifier == AceQualifier.AccessDenied) continue;
            if ((qualified.AceFlags & AceFlags.InheritOnly) != 0 &&
                (isProductRoot || qualified.SecurityIdentifier.Value == "S-1-3-0")) continue;
            if (qualified.AceQualifier != AceQualifier.AccessAllowed || qualified.IsCallback)
                throw new InvalidOperationException("Protected update object has unsupported permissions.");
            if (!Trusted(qualified.SecurityIdentifier, allowTrustedInstaller) && (unchecked((uint)qualified.AccessMask) & forbidden) != 0)
                throw new InvalidOperationException("Protected update object permits an untrusted writer.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CreateProtectedDirectory(string directory, bool isProductRoot)
    {
        const string protectedSddl = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(isProductRoot ? ProductDirectorySddl : protectedSddl,
                SecurityDescriptorRevision, out var descriptor, out _))
            throw new InvalidOperationException("Protected update storage descriptor is unavailable.", new Win32Exception(Marshal.GetLastWin32Error()));
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor };
            if (!CreateDirectory(directory, ref attributes) && Marshal.GetLastWin32Error() != 183)
                throw new InvalidOperationException("Protected update storage could not be created.", new Win32Exception(Marshal.GetLastWin32Error()));
        }
        finally { _ = LocalFree(descriptor); }
    }

    private static void ValidateExistingAncestors(string path)
    {
        var current = Path.GetFullPath(path);
        while (!string.IsNullOrWhiteSpace(current))
        {
            try
            {
                ValidateNoReparsePoint(current, "Privileged update ancestor");
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
            {
            }

            var parent = Directory.GetParent(current)?.FullName;
            if (string.IsNullOrWhiteSpace(parent) || string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
                break;
            current = parent;
        }
    }

    private static void ValidateNoReparsePoint(string path, string description)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException($"{description} contains a reparse point.");
    }

    private const uint SecurityDescriptorRevision = 1;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint SeObjectTypeFile = 1;
    private const uint ErrorSuccess = 0;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSDRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetNamedSecurityInfo(string path, uint type, uint information,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int InheritHandle; }

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr handle);
}
