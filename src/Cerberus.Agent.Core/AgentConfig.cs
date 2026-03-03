namespace Cerberus.Agent.Core;

public sealed class AgentConfig
{
    public required Uri BackendUrl { get; init; }
    public int PollIntervalSeconds { get; init; } = 30;
    public int CommandTimeoutSeconds { get; init; } = 120;
    public int OAuthRedirectPort { get; init; } = 19823;
}

