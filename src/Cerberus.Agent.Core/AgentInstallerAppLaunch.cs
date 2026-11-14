using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;

namespace Cerberus.Agent.Core;

/// <summary>Prepares the SYSTEM enrollment child before the native bundle host can extract any library.</summary>
public static class AgentInstallerAppLaunch
{
    internal const string ExtractionEnvironment = "DOTNET_BUNDLE_EXTRACT_BASE_DIR";
    internal const string ExtractionDirectory = "BundleExtraction";
    internal const string ExtractionSddl = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    /// <summary>Uses only the installed server App and a fixed protected cache; unsafe existing state is never repaired.</summary>
    [SupportedOSPlatform("windows")]
    public static ProcessStartInfo Prepare(string runtimeDirectory, string? enrollmentProof, bool rollback)
    {
        if (!AgentBuildProfile.IsServer || !AgentUpdateSecurity.IsLocalSystem())
            throw new InvalidOperationException("Installer enrollment requires the SYSTEM server helper.");
        var runtime = AgentUpdateSecurity.NormalizeRoot(runtimeDirectory);
        var executable = Path.Combine(runtime, "Cerberus.Agent.exe");
        AgentUpdateSecurity.ValidateInstalledServiceSource(executable, runtime);
        return CreateStartInfo(executable, enrollmentProof, rollback, EnsureExtractionRoot);
    }

    internal static ProcessStartInfo CreateStartInfo(string executable, string? enrollmentProof, bool rollback,
        Func<string> prepareExtractionRoot)
    {
        if (!rollback && string.IsNullOrWhiteSpace(enrollmentProof))
            throw new InvalidOperationException("Installer enrollment proof is missing.");
        // A failed directory/ACL check must stop before any start information is returned to the launcher.
        var extractionRoot = prepareExtractionRoot();
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(executable)!,
        };
        start.Environment[ExtractionEnvironment] = extractionRoot;
        if (rollback)
            start.ArgumentList.Add("--enroll-rollback");
        else
        {
            start.ArgumentList.Add("--enroll-headless");
            start.ArgumentList.Add("--proof-from-installer");
            start.ArgumentList.Add(enrollmentProof!);
            start.ArgumentList.Add("--install-service");
        }
        return start;
    }

    [SupportedOSPlatform("windows")]
    private static string EnsureExtractionRoot()
    {
        // Reuse the existing protected namespace, outside the update attempts and their retention rules.
        AgentUpdateSecurity.EnsureProtectedRoot(AgentUpdateSecurity.DefaultPrivilegedRoot);
        var parent = Path.GetDirectoryName(AgentUpdateSecurity.DefaultPrivilegedRoot)!;
        AgentUpdateSecurity.ValidateInstalledSource(parent, parent);
        var root = Path.Combine(parent, ExtractionDirectory);
        AgentUpdateSecurity.ValidateProtectedPath(root, parent, allowMissing: true);
        if (!Directory.Exists(root))
        {
            var security = new DirectorySecurity();
            security.SetSecurityDescriptorSddlForm(ExtractionSddl);
            new DirectoryInfo(root).Create(security);
        }
        // Creation may lose a race to an existing object. Do not bless it by resetting its ACL.
        AgentUpdateSecurity.ValidateProtectedPath(root, parent, allowMissing: false);
        ValidateExtractionTree(root);
        return root;
    }

    [SupportedOSPlatform("windows")]
    internal static void ValidateExtractionTree(string root)
    {
        // Include ancestor ACL authority, not only reparses and the protected product namespace.
        AgentUpdateSecurity.ValidateInstalledSource(root, root);
        if ((File.GetAttributes(root) & FileAttributes.Directory) == 0)
            throw new InvalidOperationException("Bundle extraction root is not a directory.");
        ValidateExtractionObject(root, isRoot: true);
        // The native extractor can reuse cached files, so a trusted root alone is insufficient.
        AgentUpdateSecurity.ValidateProtectedDescendants(root, path => ValidateExtractionObject(path, isRoot: false));
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateExtractionObject(string path, bool isRoot)
    {
        FileSystemSecurity security = (File.GetAttributes(path) & FileAttributes.Directory) != 0
            ? new DirectoryInfo(path).GetAccessControl()
            : new FileInfo(path).GetAccessControl();
        ValidateExtractionDescriptor(new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0), isRoot);
    }

    [SupportedOSPlatform("windows")]
    internal static void ValidateExtractionDescriptor(RawSecurityDescriptor descriptor, bool isRoot)
    {
        if (descriptor.Owner?.Value is not ("S-1-5-18" or "S-1-5-32-544") || descriptor.DiscretionaryAcl is null ||
            (descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 ||
            (isRoot && (descriptor.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0))
            throw new InvalidOperationException("Bundle extraction ownership or permissions are invalid.");
        var fullControl = (int)FileSystemRights.FullControl;
        var system = false;
        var administrators = false;
        foreach (GenericAce ace in descriptor.DiscretionaryAcl)
        {
            if (ace is not QualifiedAce access || access.IsCallback || access.AceQualifier != AceQualifier.AccessAllowed ||
                access.SecurityIdentifier.Value is not ("S-1-5-18" or "S-1-5-32-544"))
                throw new InvalidOperationException("Bundle extraction permissions are not restricted to SYSTEM and Administrators.");
            if ((access.AceFlags & AceFlags.InheritOnly) != 0) continue;
            if ((access.AccessMask & fullControl) != fullControl ||
                (isRoot && (access.AceFlags & AceFlags.NoPropagateInherit) != 0) ||
                (isRoot && (access.AceFlags & (AceFlags.ContainerInherit | AceFlags.ObjectInherit)) !=
                    (AceFlags.ContainerInherit | AceFlags.ObjectInherit)))
                throw new InvalidOperationException("Bundle extraction permissions are incomplete.");
            system |= access.SecurityIdentifier.Value == "S-1-5-18";
            administrators |= access.SecurityIdentifier.Value == "S-1-5-32-544";
        }
        if (!system || !administrators)
            throw new InvalidOperationException("Bundle extraction permissions are incomplete.");
    }
}
