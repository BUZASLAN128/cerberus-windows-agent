using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateStorageProvenanceTests
{
    [Theory]
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BA)", true)]
    [InlineData("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)", true)]
    [InlineData("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GW;;;BU)", false)]
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;WD;;;BU)", false)]
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICIIO;FA;;;BU)", false)]
    public void Descriptor_RequiresTrustedOwnersAndWritersIncludingInheritedChildren(string sddl, bool allowed)
    {
        if (!OperatingSystem.IsWindows()) return;
        var descriptor = new RawSecurityDescriptor(sddl);
        if (allowed) AgentUpdateSecurity.ValidateDescriptor(descriptor);
        else Assert.Throws<InvalidOperationException>(() => AgentUpdateSecurity.ValidateDescriptor(descriptor));
    }

    [Fact]
    public void PreseededUserOwnedTransactionAndRunner_AreRejectedWithoutAclRepairOrExecution()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.IsSystem) return; // The attack fixture specifically requires a non-SYSTEM owner.
        var root = Path.Combine(Path.GetTempPath(), "cerberus-preseed-test-" + Guid.NewGuid().ToString("N"));
        var attempt = Path.Combine(root, "attempts", "attempt-preseed");
        var runner = Path.Combine(attempt, "runner");
        Directory.CreateDirectory(runner);
        var payload = Path.Combine(runner, "Cerberus.Agent.Updater.exe");
        File.WriteAllText(payload, "inert fixture; never execute");
        var journal = Path.Combine(root, "transaction.json");
        File.WriteAllText(journal, "{\"phase\":\"awaiting_consent\",\"attemptId\":\"preseed\"}");
        File.WriteAllText(Path.Combine(runner, "inventory.json"), "{\"Files\":{\"Cerberus.Agent.Updater.exe\":\"forged\"}}");
        // Reproduce protected attacker + SYSTEM ACLs: parent inheritance/repair cannot remove the attacker's grant.
        var attacker = identity.User!;
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        foreach (var directory in new[] { root, Path.GetDirectoryName(attempt)!, attempt, runner })
        {
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            acl.AddAccessRule(new FileSystemAccessRule(attacker, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(directory).SetAccessControl(acl);
        }
        var before = Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories).Prepend(root)
            .ToDictionary(path => path, path => File.GetAttributes(path).HasFlag(FileAttributes.Directory)
                ? new DirectoryInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All)
                : new FileInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
        try
        {
            Assert.Throws<InvalidOperationException>(() => AgentUpdateSecurity.EnsureProtectedRoot(root));
            Assert.Throws<InvalidOperationException>(() => AgentUpdateSecurity.ValidateProtectedPath(journal, root, false));
            Assert.Throws<InvalidOperationException>(() => AgentUpdateRunnerFiles.Prepare(root, attempt));
            foreach (var (path, acl) in before)
                Assert.Equal(acl, File.GetAttributes(path).HasFlag(FileAttributes.Directory)
                    ? new DirectoryInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All)
                    : new FileInfo(path).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.All));
            Assert.Equal("inert fixture; never execute", File.ReadAllText(payload));
            Assert.Contains("awaiting_consent", File.ReadAllText(journal));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void UnelevatedBootstrap_FailsBeforeCreatingProtectedRootOrInvokingPrivilegedAction()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var identity = WindowsIdentity.GetCurrent();
        if (identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return;
        var root = Path.Combine(Path.GetTempPath(), "cerberus-no-elevation-test-" + Guid.NewGuid().ToString("N"));
        var invoked = false;
        Assert.Throws<UnauthorizedAccessException>(() => AgentUpdateStoragePrivilege.Run(() => invoked = true));
        Assert.False(invoked);
        Assert.Throws<UnauthorizedAccessException>(() => AgentUpdateSecurity.EnsureProtectedRoot(root));
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public void BitsJobVtable_MatchesSdkOrderAndPreservedHresultIncludingAddFileSlot()
    {
        // Microsoft win32metadata Bits.h IBackgroundCopyJob (base IUnknown contributes slots 0..2).
        var type = typeof(AgentUpdateBitsDownloader).GetNestedType("IBackgroundCopyJob", BindingFlags.NonPublic)!;
        var expected = new[] { "AddFileSet", "AddFile", "EnumFiles", "Suspend", "Resume", "Cancel", "Complete", "GetId", "GetType", "GetProgress", "GetTimes", "GetState", "GetError", "GetOwner", "SetDisplayName", "GetDisplayName", "SetDescription", "GetDescription", "SetPriority", "GetPriority", "SetNotifyFlags", "GetNotifyFlags", "SetNotifyInterface", "GetNotifyInterface", "SetMinimumRetryDelay", "GetMinimumRetryDelay", "SetNoProgressTimeout", "GetNoProgressTimeout", "GetErrorCount", "SetProxySettings", "GetProxySettings", "TakeOwnership" };
        var methods = type.GetMethods().OrderBy(method => method.MetadataToken).ToArray();
        Assert.Equal(expected, methods.Select(method => method.Name));
        Assert.Equal(new Guid("37668D37-507E-4160-9316-26306D150B12"), type.GUID);
        Assert.All(methods, method =>
        {
            Assert.Equal(typeof(int), method.ReturnType);
            Assert.True(method.MethodImplementationFlags.HasFlag(MethodImplAttributes.PreserveSig));
        });
        Assert.All(methods.Single(method => method.Name == "AddFile").GetParameters(), parameter =>
            Assert.Equal(UnmanagedType.LPWStr, parameter.GetCustomAttribute<MarshalAsAttribute>()!.Value));
    }

    [Theory]
    [InlineData("IBackgroundCopyManager", "5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C", "CreateJob,GetJob,EnumJobs,GetErrorDescription")]
    [InlineData("IEnumBackgroundCopyJobs", "1AF4F612-3B71-466F-8F58-7B6F73AC57AD", "Next,Skip,Reset,Clone,GetCount")]
    [InlineData("IEnumBackgroundCopyFiles", "CA51E165-C365-424C-8D41-24AAA4FF3C40", "Next,Skip,Reset,Clone,GetCount")]
    [InlineData("IBackgroundCopyFile", "01B7BD23-FB88-4A77-8490-5891D3E4653A", "GetRemoteName,GetLocalName,GetProgress")]
    public void BitsCompanionVtables_MatchSdk(string name, string guid, string expected)
    {
        var type = typeof(AgentUpdateBitsDownloader).GetNestedType(name, BindingFlags.NonPublic)!;
        var methods = type.GetMethods().OrderBy(method => method.MetadataToken).ToArray();
        Assert.Equal(expected.Split(','), methods.Select(method => method.Name));
        Assert.Equal(new Guid(guid), type.GUID);
        Assert.Equal(ComInterfaceType.InterfaceIsIUnknown, type.GetCustomAttribute<InterfaceTypeAttribute>()!.Value);
        Assert.All(methods, method =>
        {
            Assert.Equal(typeof(int), method.ReturnType);
            Assert.True(method.MethodImplementationFlags.HasFlag(MethodImplAttributes.PreserveSig));
        });
    }

    [Fact]
    public void BitsUsedProgressAndEnumerationParameters_MatchNativeWidthsAndPointerDirections()
    {
        Type Nested(string name) => typeof(AgentUpdateBitsDownloader).GetNestedType(name, BindingFlags.NonPublic)!;
        var progress = Nested("BackgroundCopyJobProgress");
        Assert.Equal(24, Marshal.SizeOf(progress));
        Assert.Equal(0, Marshal.OffsetOf(progress, "BytesTotal").ToInt32());
        Assert.Equal(8, Marshal.OffsetOf(progress, "BytesTransferred").ToInt32());
        Assert.Equal(16, Marshal.OffsetOf(progress, "FilesTotal").ToInt32());
        Assert.Equal(20, Marshal.OffsetOf(progress, "FilesTransferred").ToInt32());
        var getProgress = Nested("IBackgroundCopyJob").GetMethod("GetProgress")!.GetParameters().Single();
        Assert.Equal(progress.MakeByRefType(), getProgress.ParameterType);
        Assert.True(getProgress.IsOut);
        foreach (var name in new[] { "IEnumBackgroundCopyJobs", "IEnumBackgroundCopyFiles" })
        {
            var next = Nested(name).GetMethod("Next")!.GetParameters();
            Assert.Equal(typeof(uint), next[0].ParameterType);
            Assert.True(next[1].IsOut);
            Assert.Equal(UnmanagedType.Interface, next[1].GetCustomAttribute<MarshalAsAttribute>()!.Value);
            Assert.Equal(typeof(uint).MakeByRefType(), next[2].ParameterType);
            Assert.True(next[2].IsOut);
        }
        foreach (var name in new[] { "SetNotifyInterface", "GetNotifyInterface" })
            Assert.Equal(UnmanagedType.IUnknown, Nested("IBackgroundCopyJob").GetMethod(name)!.GetParameters().Single().GetCustomAttribute<MarshalAsAttribute>()!.Value);
    }
}
