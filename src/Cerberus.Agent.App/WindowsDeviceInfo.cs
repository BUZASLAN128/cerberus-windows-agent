using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Cerberus.Agent.App;

internal static class WindowsDeviceInfo
{
    public static string GetAgentVersion()
    {
        try
        {
            var v = typeof(Program).Assembly.GetName().Version;
            return v?.ToString() ?? "0.0.0";
        }
        catch
        {
            return "0.0.0";
        }
    }

    public static string ComputeDeviceFingerprint()
    {
        var machine = Environment.MachineName ?? "unknown";
        var guid = ReadMachineGuid() ?? "unknown";
        var raw = $"{machine}:{guid}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? ReadMachineGuid()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\\Microsoft\\Cryptography");
            return key?.GetValue("MachineGuid")?.ToString();
        }
        catch
        {
            return null;
        }
    }
}

