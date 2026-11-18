namespace Cerberus.Agent.Core;

/// <summary>
/// Build-time profile selected with the MSBuild property <c>AgentBuildProfile</c>
/// (see Directory.Build.props). The value is a compile-time constant; there is
/// no runtime switch.
/// </summary>
public static class AgentBuildProfile
{
#if CERBERUS_SERVER_PROFILE
    public static readonly bool IsServer = true;
#else
    public static readonly bool IsServer = false;
#endif
}
