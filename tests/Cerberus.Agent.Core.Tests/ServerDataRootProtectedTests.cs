#if CERBERUS_SERVER_PROFILE
using System.Security.AccessControl;
using System.Security.Principal;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Temp folders only. Owner and DACL changes need an elevated (non-SYSTEM) token; without it these cases return
// early, like the existing ServerDataRootTests.
public sealed class ServerDataRootProtectedTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cerberus-dataroot-prot-" + Guid.NewGuid().ToString("N"));

    public ServerDataRootProtectedTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static bool CanRun(out SecurityIdentifier user)
    {
        using var identity = WindowsIdentity.GetCurrent();
        user = identity.User!;
        return !identity.IsSystem && new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void AddChildOwnedBy(string root, SecurityIdentifier user)
    {
        var child = Path.Combine(root, "pre-created.txt");
        File.WriteAllText(child, "x");
        var info = new FileInfo(child);
        var security = info.GetAccessControl();
        security.SetOwner(user);
        info.SetAccessControl(security);
        Assert.Equal(user, new FileInfo(child).GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
    }

    [Fact]
    public void Already_protected_root_still_refuses_a_child_owned_by_the_user()
    {
        if (!CanRun(out var user)) return;
        var root = Path.Combine(_root, "data");
        Assert.True(ServerDataRoot.EnsureProtected(root));
        AddChildOwnedBy(root, user);

        Assert.False(ServerDataRoot.EnsureProtected(root));
        Assert.False(ServerDataRoot.EnsureProtected(root));
    }

    [Fact]
    public void Already_protected_root_refuses_a_reparse_point_entry()
    {
        if (!CanRun(out _)) return;
        var root = Path.Combine(_root, "data");
        Assert.True(ServerDataRoot.EnsureProtected(root));
        var target = Directory.CreateDirectory(Path.Combine(_root, "target")).FullName;
        Directory.CreateSymbolicLink(Path.Combine(root, "logs"), target);

        Assert.False(ServerDataRoot.EnsureProtected(root));
        Assert.False(ServerDataRoot.EnsureProtected(root));
    }

    // The protected DACL is applied by something else first (for example the MSI); it must not make the root look vetted.
    private static string ProtectedRootAppliedExternally(string path)
    {
        var dir = Directory.CreateDirectory(path);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(acl);
        return dir.FullName;
    }

    [Fact]
    public void Externally_protected_root_refuses_a_planted_user_owned_directory_on_every_call()
    {
        if (!CanRun(out var user)) return;
        var root = ProtectedRootAppliedExternally(Path.Combine(_root, "data"));
        var planted = Directory.CreateDirectory(Path.Combine(root, "logs")).FullName;
        var security = new DirectoryInfo(planted).GetAccessControl();
        security.SetOwner(user);
        new DirectoryInfo(planted).SetAccessControl(security);

        Assert.False(ServerDataRoot.EnsureProtected(root));
        Assert.False(ServerDataRoot.EnsureProtected(root));
    }

    [Fact]
    public void Externally_protected_root_refuses_a_planted_junction_on_every_call()
    {
        if (!CanRun(out _)) return;
        var root = ProtectedRootAppliedExternally(Path.Combine(_root, "data"));
        var target = Directory.CreateDirectory(Path.Combine(_root, "target")).FullName;
        using (var mk = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe",
            $"/c mklink /J \"{Path.Combine(root, "logs")}\" \"{target}\"")
        { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!)
        {
            mk.WaitForExit();
            Assert.Equal(0, mk.ExitCode);
        }

        Assert.False(ServerDataRoot.EnsureProtected(root));
        Assert.False(ServerDataRoot.EnsureProtected(root));
    }

    [Fact]
    public void Entries_created_after_the_gate_are_owned_by_administrators_and_pass_the_next_call()
    {
        if (!CanRun(out _)) return;
        var root = Path.Combine(_root, "data");
        Assert.True(ServerDataRoot.EnsureProtected(root));
        var child = Path.Combine(root, "written-later.txt");
        File.WriteAllText(child, "x");
        Directory.CreateDirectory(Path.Combine(root, "logs"));

        Assert.Equal(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            new FileInfo(child).GetAccessControl().GetOwner(typeof(SecurityIdentifier)));
        Assert.True(ServerDataRoot.EnsureProtected(root));
    }

    [Fact]
    public void First_hardening_still_refuses_a_child_owned_by_the_user()
    {
        if (!CanRun(out var user)) return;
        var root = Directory.CreateDirectory(Path.Combine(_root, "data")).FullName;
        AddChildOwnedBy(root, user);

        Assert.False(ServerDataRoot.EnsureProtected(root));
    }
}
#endif
