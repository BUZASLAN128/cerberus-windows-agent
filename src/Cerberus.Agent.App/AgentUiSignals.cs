namespace Cerberus.Agent.App;

public static class AgentUiSignals
{
    public const string Open = "open";
    public const string Connect = "connect";
    public const string CheckUpdates = "check-updates";
    public const string UpdateNow = "update-now";

    private static readonly HashSet<string> Allowed = new(StringComparer.Ordinal)
    {
        Open,
        Connect,
        CheckUpdates,
        UpdateNow,
    };

    public static bool TryNormalize(string? value, out string signal)
    {
        signal = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var normalized = value.Trim().ToLowerInvariant();
        if (!Allowed.Contains(normalized))
            return false;

        signal = normalized;
        return true;
    }

    public static string? NormalizeOrNull(string? value)
        => TryNormalize(value, out var signal) ? signal : null;
}
