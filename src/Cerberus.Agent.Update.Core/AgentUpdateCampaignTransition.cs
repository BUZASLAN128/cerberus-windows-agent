namespace Cerberus.Agent.Core;

/// <summary>Lab progression follows the installed predecessor, never just membership of an allowed set.</summary>
public static class AgentUpdateCampaignTransition
{
    public static string Release(string version) => version.Split('+', 2)[0];

    public static void RequireNext(IReadOnlyList<string> versions, string installedVersion, string targetVersion)
    {
        var installed = Release(installedVersion);
        var index = -1;
        for (var i = 0; i < versions.Count; i++) if (versions[i] == installed) { index = i; break; }
        if (index < 0 || index + 1 >= versions.Count || versions[index + 1] != targetVersion)
            throw new InvalidOperationException("Development update must be the immediate successor of the installed version.");
    }
}
