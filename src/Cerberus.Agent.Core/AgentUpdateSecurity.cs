using System.ComponentModel;
using System.Runtime.InteropServices;
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

    public static void EnsureProtectedRoot(string root)
    {
        var fullRoot = NormalizeRoot(root);
        ValidateExistingAncestors(fullRoot);

        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(fullRoot);
            return;
        }

        var protectionTargets = GetProtectionTargets(fullRoot).ToArray();
        var productRoot = Path.Combine(
            NormalizeRoot(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)), "CerberusAgent");
        var productRootWasMissing = !Directory.Exists(productRoot);
        foreach (var directory in protectionTargets)
        {
            ValidateExistingAncestors(directory);
            var existed = Directory.Exists(directory);
            Directory.CreateDirectory(directory);
            ValidateNoReparsePoint(directory, "Privileged update directory");
            // Shared ancestors also contain lifecycle/provisioning state. Their
            // owner sets their policy; an update record write must not reset it.
            if (existed && !string.Equals(directory, fullRoot, StringComparison.OrdinalIgnoreCase))
                continue;
            // Keep the product root restrictive while its privileged children
            // are being created, then restore its narrow signal-file grants.
            ApplyProtectedAcl(directory, isProductRoot: false);
        }

        if (productRootWasMissing && protectionTargets.Contains(productRoot, StringComparer.OrdinalIgnoreCase))
            ApplyProtectedAcl(productRoot, isProductRoot: true);

        ValidateNoReparsePoint(fullRoot, "Privileged update root");
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
        var fullRoot = NormalizeRoot(trustedRoot);
        var fullPath = Path.GetFullPath(path);
        if (!IsUnderDirectory(fullPath, fullRoot))
            throw new InvalidOperationException("Update path is outside protected storage.");

        ValidateExistingAncestors(fullPath);
        if (!allowMissing && !File.Exists(fullPath) && !Directory.Exists(fullPath))
            throw new FileNotFoundException("Protected update item was not found.");

        try
        {
            ValidateNoReparsePoint(fullPath, "Protected update item");
        }
        catch (Exception ex) when (allowMissing && (ex is FileNotFoundException or DirectoryNotFoundException))
        {
        }
    }

    public static bool IsUnderDirectory(string path, string directory)
    {
        var fullPath = Path.GetFullPath(path);
        var fullDirectory = NormalizeRoot(directory);
        return string.Equals(fullPath, fullDirectory, StringComparison.OrdinalIgnoreCase) ||
               fullPath.StartsWith(Path.EndsInDirectorySeparator(fullDirectory) ? fullDirectory : fullDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> GetProtectionTargets(string fullRoot)
    {
        var defaultRoot = NormalizeRoot(DefaultPrivilegedRoot);
        if (!string.Equals(fullRoot, defaultRoot, StringComparison.OrdinalIgnoreCase))
            return new[] { fullRoot };

        var commonData = NormalizeRoot(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var productRoot = Path.Combine(commonData, "CerberusAgent");
        var privilegedRoot = Path.Combine(productRoot, PrivilegedDirectoryName);
        return new[] { productRoot, privilegedRoot, fullRoot };
    }

    private static void ApplyProtectedAcl(string directory, bool isProductRoot)
    {
        // O:SYG:SYD:P makes SYSTEM the owner and removes inherited grants.  The
        // explicit ACEs leave administrators in control while standard users can
        // inspect state but cannot create, replace, rename, or delete update data.
        const string protectedDirectorySddl =
            "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";
        // CerberusAgent also contains non-privileged service signals. Keep that
        // product root writable only for files while denying standard-user
        // deletion of the Privileged child; the Privileged and Updates ACLs
        // below remain SYSTEM/Admin-only.
        const string productRootSddl =
            "O:SYG:SYD:P(D;;DC;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;GRGWGX;;;BU)(A;OI;GRGWGX;;;BU)";
        var securityDescriptorSddl = isProductRoot ? productRootSddl : protectedDirectorySddl;

        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                securityDescriptorSddl,
                SecurityDescriptorRevision,
                out var securityDescriptor,
                out _))
        {
            throw new InvalidOperationException(
                "Privileged update storage protection could not be established.",
                new Win32Exception(Marshal.GetLastWin32Error()));
        }

        try
        {
            if (!GetSecurityDescriptorOwner(securityDescriptor, out var owner, out _) ||
                !GetSecurityDescriptorDacl(securityDescriptor, out var daclPresent, out var dacl, out _) ||
                !daclPresent)
            {
                throw new InvalidOperationException("Privileged update storage protection could not be established.");
            }

            var result = SetNamedSecurityInfo(
                directory,
                SeObjectTypeFile,
                OwnerSecurityInformation | DaclSecurityInformation | ProtectedDaclSecurityInformation,
                owner,
                IntPtr.Zero,
                dacl,
                IntPtr.Zero);
            if (result != ErrorSuccess)
                throw new InvalidOperationException(
                    "Privileged update storage protection could not be established.",
                    new Win32Exception((int)result));
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
        }
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
    private const uint ProtectedDaclSecurityInformation = 0x80000000;
    private const uint SeObjectTypeFile = 1;
    private const uint ErrorSuccess = 0;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSDRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorOwner(
        IntPtr securityDescriptor,
        out IntPtr owner,
        out bool ownerDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(
        IntPtr securityDescriptor,
        out bool daclPresent,
        out IntPtr dacl,
        out bool daclDefaulted);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint SetNamedSecurityInfo(
        string objectName,
        uint objectType,
        uint securityInfo,
        IntPtr owner,
        IntPtr group,
        IntPtr dacl,
        IntPtr sacl);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr handle);
}
