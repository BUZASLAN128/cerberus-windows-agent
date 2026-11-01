namespace Cerberus.Agent.Core;

/// <summary>The worker's protected enrollment binding no longer identifies the current registration.</summary>
public sealed class AgentRegistrationChangedException()
    : InvalidOperationException("The active product enrollment changed; restart is required.");
