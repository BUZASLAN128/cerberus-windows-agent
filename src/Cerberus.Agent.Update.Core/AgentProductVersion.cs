using System.Reflection;

namespace Cerberus.Agent.Core;

public static class AgentProductVersion
{
    public static string Get(Assembly fallback)
    {
        try
        {
            var info = GetInformationalVersion(fallback);
            if (!string.IsNullOrWhiteSpace(info))
                return info;

            var v = (Assembly.GetEntryAssembly() ?? fallback).GetName().Version;
            return v?.ToString() ?? "0.0.0";
        }
        catch
        {
            return "0.0.0";
        }
    }

    internal static string GetInformationalVersion(Assembly fallback)
    {
        var info = (Assembly.GetEntryAssembly() ?? fallback)
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        if (string.IsNullOrWhiteSpace(info))
            return "";

        return info.Split('+', 2, StringSplitOptions.TrimEntries)[0].Trim();
    }
}
