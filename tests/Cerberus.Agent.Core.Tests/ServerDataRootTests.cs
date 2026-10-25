#if CERBERUS_SERVER_PROFILE
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Temp folders only; the real %ProgramData% data folder is never touched.
public sealed class ServerDataRootTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cerberus-dataroot-" + Guid.NewGuid().ToString("N"));

    public ServerDataRootTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static bool Elevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    [Fact]
    public void A_file_at_the_data_folder_path_is_refused()
    {
        var path = Path.Combine(_root, "data");
        File.WriteAllText(path, "x");

        Assert.False(ServerDataRoot.EnsureProtected(path));
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void A_junction_at_the_data_folder_path_is_refused_and_its_target_is_left_alone()
    {
        var target = Directory.CreateDirectory(Path.Combine(_root, "target")).FullName;
        var link = Path.Combine(_root, "link");
        using (var mk = Process.Start(new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
        { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!)
        {
            mk.WaitForExit();
            Assert.Equal(0, mk.ExitCode);
        }
        var before = new DirectoryInfo(target).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);

        Assert.False(ServerDataRoot.EnsureProtected(link));
        Assert.Equal(before, new DirectoryInfo(target).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access));
    }

    [Fact]
    public void An_existing_folder_owned_by_a_standard_user_is_refused_and_not_modified()
    {
        if (Elevated()) return; // an elevated token owns new folders as Administrators
        var path = Directory.CreateDirectory(Path.Combine(_root, "data")).FullName;
        var before = new DirectoryInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);

        Assert.False(ServerDataRoot.EnsureProtected(path));
        Assert.Equal(before, new DirectoryInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access));
    }

    [Fact]
    public void A_new_or_trusted_folder_gets_a_protected_system_and_administrators_only_dacl()
    {
        if (!Elevated()) return; // owner and DACL changes need an elevated token
        var created = Path.Combine(_root, "created");
        var existing = Directory.CreateDirectory(Path.Combine(_root, "existing")).FullName;
        File.WriteAllText(Path.Combine(existing, "enrollment-fingerprint.txt"), "x");

        Assert.True(ServerDataRoot.EnsureProtected(created));
        Assert.True(ServerDataRoot.EnsureProtected(existing));

        foreach (var path in new[] { created, existing })
        {
            var acl = new DirectoryInfo(path).GetAccessControl();
            Assert.True(acl.AreAccessRulesProtected);
            var sids = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Select(r => ((SecurityIdentifier)r.IdentityReference).Value).Order().ToArray();
            Assert.Equal(["S-1-5-18", "S-1-5-32-544"], sids);
        }
    }
}
#endif
