using System.Runtime.InteropServices;

namespace Cerberus.Agent.Core;

public static class AgentUpdateBootIdentity
{
    /// <summary>Windows' kernel boot identifier, not a service restart timestamp or estimated uptime.</summary>
    public static string Read()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException();
        var value = new SystemBootEnvironmentInformation();
        var status = NtQuerySystemInformation(90, ref value, Marshal.SizeOf<SystemBootEnvironmentInformation>(), out _);
        if (status != 0 || value.BootIdentifier == Guid.Empty)
            throw new InvalidOperationException("Windows boot identity is unavailable.");
        return value.BootIdentifier.ToString("N");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemBootEnvironmentInformation
    {
        public Guid BootIdentifier;
        public uint FirmwareType;
        public ulong BootFlags;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int informationClass, ref SystemBootEnvironmentInformation information, int length, out int returnLength);
}
