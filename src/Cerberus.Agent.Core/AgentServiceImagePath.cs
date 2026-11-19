namespace Cerberus.Agent.Core;

public static class AgentServiceImagePath
{
    public static string? ExtractExecutablePath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
            return null;

        var value = imagePath.Trim();
        if (value.StartsWith("\"", StringComparison.Ordinal))
        {
            var endQuote = value.IndexOf('"', startIndex: 1);
            return endQuote > 1 ? value[1..endQuote] : null;
        }

        var serviceArg = value.IndexOf(" --service", StringComparison.OrdinalIgnoreCase);
        if (serviceArg > 0)
            return value[..serviceArg].Trim();

        var firstSpace = value.IndexOf(' ');
        return firstSpace > 0 ? value[..firstSpace].Trim() : value;
    }

    public static bool Matches(string? installedExePath, string currentExePath)
    {
        if (string.IsNullOrWhiteSpace(installedExePath) || string.IsNullOrWhiteSpace(currentExePath))
            return false;

        try
        {
            installedExePath = Path.GetFullPath(installedExePath.Trim());
            currentExePath = Path.GetFullPath(currentExePath.Trim());
        }
        catch
        {
            installedExePath = installedExePath.Trim();
            currentExePath = currentExePath.Trim();
        }

        return string.Equals(installedExePath, currentExePath, StringComparison.OrdinalIgnoreCase);
    }
}
