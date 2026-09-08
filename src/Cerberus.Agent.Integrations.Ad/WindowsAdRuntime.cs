using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Cerberus.Agent.Integrations.Ad;

internal sealed record AdMachineEvidence(bool IsSystem, int Role, uint Flags, Guid DomainGuid, string DomainDnsName, string MachineName);

internal static class WindowsAdRuntime
{
    internal static AdMachineEvidence Read()
    {
        if (!OperatingSystem.IsWindows()) throw new AdOperationDeniedException("ad_windows_required");
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem || identity.ImpersonationLevel != TokenImpersonationLevel.None)
            throw new AdOperationDeniedException("ad_system_identity_required");
        if (DsRoleGetPrimaryDomainInformation(IntPtr.Zero, 1, out var pointer) != 0 || pointer == IntPtr.Zero)
            throw new AdOperationDeniedException("ad_machine_role_unavailable");
        try
        {
            var info = Marshal.PtrToStructure<DomainInfo>(pointer);
            return new(true, info.Role, info.Flags, info.DomainGuid,
                Marshal.PtrToStringUni(info.DomainDnsName) ?? "", Environment.MachineName);
        }
        finally { DsRoleFreeMemory(pointer); }
    }

    internal static void Validate(AdMachineEvidence evidence, AdScope scope)
    {
        if (!evidence.IsSystem) throw new AdOperationDeniedException("ad_system_identity_required");
        // DSROLE_ROLE_MEMBER_WORKSTATION=1, MEMBER_SERVER=3. Both DC roles and standalone roles fail closed.
        if (evidence.Role is 4 or 5 || (evidence.Flags & 0x1) != 0)
            throw new AdOperationDeniedException("ad_domain_controller_denied");
        if (evidence.Role is not (1 or 3) || (evidence.Flags & 0x01000000) == 0 ||
            evidence.DomainGuid == Guid.Empty || string.IsNullOrWhiteSpace(evidence.DomainDnsName))
            throw new AdOperationDeniedException("ad_not_domain_member");
        if (evidence.DomainGuid != scope.DomainGuid ||
            !StringComparer.OrdinalIgnoreCase.Equals(evidence.DomainDnsName, scope.DomainDnsName))
            throw new AdOperationDeniedException("ad_domain_mismatch");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DomainInfo
    {
        public int Role;
        public uint Flags;
        public IntPtr DomainFlatName;
        public IntPtr DomainDnsName;
        public IntPtr ForestDnsName;
        public Guid DomainGuid;
    }

    [DllImport("netapi32.dll", ExactSpelling = true)]
    private static extern uint DsRoleGetPrimaryDomainInformation(IntPtr server, int level, out IntPtr buffer);
    [DllImport("netapi32.dll", ExactSpelling = true)]
    private static extern void DsRoleFreeMemory(IntPtr buffer);
}
