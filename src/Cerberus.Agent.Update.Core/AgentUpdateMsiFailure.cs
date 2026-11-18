namespace Cerberus.Agent.Core;

public enum AgentUpdateMsiFailureKind
{
    Busy,
    HealthRollback,
    Environment,
    InstallerFailed,
}

public static class AgentUpdateMsiFailure
{
    public static AgentUpdateMsiFailureKind Classify(
        int exitCode, Stream? log, AgentInstallerHealthPhase? rollbackPhase)
        => throw new NotImplementedException();
}
