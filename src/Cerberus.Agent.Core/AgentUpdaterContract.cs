namespace Cerberus.Agent.Core;

public static class AgentUpdaterContract
{
    public const string AttemptArgument = "--attempt";
    public const string PlanSchema = "agent.update.plan.v2";
    public const string JournalSchema = "agent.update.journal.v1";
    public const string LaunchRequestedPhase = "launch_requested";
    public const string InstallMayHaveStartedPhase = "install_may_have_started";
    public const string EulaAcceptedProperty = "CERBERUS_EULA_ACCEPTED";
    public const string LabTransactionProperty = "CERBERUS_LAB_TRANSACTION";
    public const string RequireBackendProperty = "CERBERUS_UPDATE_REQUIRE_BACKEND";
    public static IReadOnlyList<int> SuccessExitCodes { get; } = Array.AsReadOnly(new[] { 0, 3010 });
    public const string InstallerTransactionsDirectoryName = "installer-transactions";
}
