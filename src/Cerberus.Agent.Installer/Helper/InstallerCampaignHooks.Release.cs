namespace Cerberus.Agent.Installer.Helper;

// Compiled only with -p:ExcludeUpdateCampaignCode=true. Each member does what the campaign admission
// does without a compiled campaign policy: nothing is admitted and an unsigned runtime is never allowed.
internal static class InstallerCampaignHooks
{
    internal static void Begin(Guid product, string version, string? transaction) { }

    internal static bool AllowRuntime(string runtime, Guid product, string version, string? transaction) => false;

    internal static void Complete(Guid product, string version, string? transaction) { }

    internal static void Rollback(Guid product, string version, string? transaction) { }
}
