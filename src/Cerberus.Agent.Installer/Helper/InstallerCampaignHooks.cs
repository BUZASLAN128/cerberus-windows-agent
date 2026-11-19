using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Installer.Helper;

// Compiled unless -p:ExcludeUpdateCampaignCode=true; InstallerCampaignHooks.Release.cs replaces it then.
internal static class InstallerCampaignHooks
{
    internal static void Begin(Guid product, string version, string? transaction)
        => AgentUpdateLabRuntimeAdmission.Begin(product, version, transaction);

    internal static bool AllowRuntime(string runtime, Guid product, string version, string? transaction)
        => AgentUpdateLabRuntimeAdmission.AllowRuntime(runtime, product, version, transaction);

    internal static void Complete(Guid product, string version, string? transaction)
        => AgentUpdateLabRuntimeAdmission.Complete(product, version, transaction);

    internal static void Rollback(Guid product, string version, string? transaction)
        => AgentUpdateLabRuntimeAdmission.Rollback(product, version, transaction);
}
