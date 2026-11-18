using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

public static class AgentVersionComparer
{
    private static readonly Regex VersionPartRegex = new(@"\d+", RegexOptions.Compiled);

    public static int? CompareReleaseCore(string? left, string? right)
    {
        var leftParts = ParseReleaseCore(left);
        var rightParts = ParseReleaseCore(right);
        if (leftParts is null || rightParts is null)
            return null;

        for (var i = 0; i < leftParts.Length; i++)
        {
            var compare = leftParts[i].CompareTo(rightParts[i]);
            if (compare != 0)
                return compare;
        }

        return 0;
    }

    private static int[]? ParseReleaseCore(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var core = value.Trim().Split(new[] { '-', '+' }, 2, StringSplitOptions.TrimEntries)[0];
        var parts = VersionPartRegex.Matches(core).Select(match => int.Parse(match.Value)).Take(4).ToList();
        if (parts.Count == 0)
            return null;

        while (parts.Count < 4)
            parts.Add(0);

        return parts.ToArray();
    }
}
