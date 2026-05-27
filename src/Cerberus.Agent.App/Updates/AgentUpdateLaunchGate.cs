using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal sealed class AgentUpdateLaunchGate
{
    private readonly object _sync = new();
    private readonly TimeSpan _cooldown;
    private string? _activeKey;
    private DateTimeOffset _activeSinceUtc;

    public AgentUpdateLaunchGate(TimeSpan cooldown)
    {
        if (cooldown <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(cooldown), "Update launch cooldown must be positive.");

        _cooldown = cooldown;
    }

    public bool TryBegin(AgentUpdateCheckResult check, DateTimeOffset nowUtc)
    {
        if (!check.Available)
            return false;

        var key = BuildKey(check);
        lock (_sync)
        {
            if (string.Equals(_activeKey, key, StringComparison.Ordinal) &&
                nowUtc - _activeSinceUtc < _cooldown)
            {
                return false;
            }

            _activeKey = key;
            _activeSinceUtc = nowUtc;
            return true;
        }
    }

    public void Clear(AgentUpdateCheckResult check)
    {
        var key = BuildKey(check);
        lock (_sync)
        {
            if (string.Equals(_activeKey, key, StringComparison.Ordinal))
            {
                _activeKey = null;
                _activeSinceUtc = default;
            }
        }
    }

    internal static string BuildKey(AgentUpdateCheckResult check)
        => string.Join(
            "|",
            Normalize(check.Channel),
            Normalize(check.Version),
            Normalize(check.ArtifactKind),
            Normalize(check.ManifestUrl));

    private static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value) ? "-" : value.Trim().ToLowerInvariant();
}
