namespace Cerberus.Agent.Core;

internal enum AgentUpdateWatchHostMode
{
    None,
    Watch,
    ScmFailure,
    Probe,
}

internal readonly record struct AgentUpdateWatchHostArgs(AgentUpdateWatchHostMode Mode, string? Nonce)
{
    public const string WatchArgument = "--watch";
    public const string ScmFailureArgument = "--scm-failure";
    public const string ProbeArgument = "--probe";

    public static bool TryParse(IReadOnlyList<string> args, out AgentUpdateWatchHostArgs parsed)
    {
        switch (args)
        {
            case [WatchArgument]:
                parsed = new(AgentUpdateWatchHostMode.Watch, null);
                return true;
            case [ScmFailureArgument]:
                parsed = new(AgentUpdateWatchHostMode.ScmFailure, null);
                return true;
            case [ProbeArgument, var nonce] when AgentUpdateSecurity.IsSafeAttemptId(nonce):
                parsed = new(AgentUpdateWatchHostMode.Probe, nonce);
                return true;
            default:
                parsed = default;
                return false;
        }
    }
}
