using Microsoft.Win32;

namespace Cerberus.Agent.Integrations.Ad;

public sealed record LocalUserCommandPolicy(bool CreateEnabled)
{
    private const string CreateEnabledEnvVar = "CERBERUS_AGENT_LOCAL_USER_CREATE_ENABLED";
    private const string RegistryPath = @"SOFTWARE\Cerberus\WindowsAgent";
    private const string RegistryValueName = "localUserCreateEnabled";

    public static LocalUserCommandPolicy CreateDisabled { get; } = new(false);
    public static LocalUserCommandPolicy CreateEnabledPolicy { get; } = new(true);

    public static LocalUserCommandPolicy FromEnvironmentAndRegistry()
        => new(ReadBool(Environment.GetEnvironmentVariable(CreateEnabledEnvVar))
               ?? ReadRegistryBool()
               ?? false);

    public static void WriteRegistryCreateEnabled(bool enabled)
    {
        using var key = Registry.LocalMachine.CreateSubKey(RegistryPath, writable: true)
            ?? throw new InvalidOperationException("Cerberus Windows Agent registry policy path could not be opened.");
        key.SetValue(RegistryValueName, enabled ? 1 : 0, RegistryValueKind.DWord);
    }

    private static bool? ReadRegistryBool()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: false);
            return ReadBool(Convert.ToString(key?.GetValue(RegistryValueName)));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            return null;
        }
    }

    private static bool? ReadBool(string? raw)
    {
        var value = (raw ?? "").Trim();
        if (value.Length == 0)
            return null;
        if (string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "on", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(value, "0", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "false", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "no", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "off", StringComparison.OrdinalIgnoreCase))
            return false;
        return null;
    }
}
