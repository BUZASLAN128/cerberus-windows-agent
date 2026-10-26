using System.Runtime.InteropServices;

namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

/// <summary>Whether the system audit policy logs failures for the Logon subcategory (needs LocalSystem rights).</summary>
internal static class FailedLogonAuditPolicy
{
    private const uint PolicyAuditEventFailure = 0x2;
    private static readonly Guid LogonSubcategory = new("0CCE9215-69AE-11D9-BED3-505054503030");

    internal static bool? MapFailureFlag(uint auditingInformation) => (auditingInformation & PolicyAuditEventFailure) != 0;

    internal static bool? ReadFailureEnabled()
    {
        var pointer = IntPtr.Zero;
        try
        {
            if (!AuditQuerySystemPolicy([LogonSubcategory], 1, out pointer) || pointer == IntPtr.Zero)
                return null;
            return MapFailureFlag(Marshal.PtrToStructure<AuditPolicyInformation>(pointer).AuditingInformation);
        }
        catch (Exception)
        {
            return null;
        }
        finally
        {
            if (pointer != IntPtr.Zero)
                AuditFree(pointer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] subCategoryGuids, uint policyCount, out IntPtr auditPolicy);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);
}
