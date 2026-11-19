namespace Cerberus.Agent.Core;

internal static class AgentUpdateWatchJournal
{
    public const string CommittedWatch = "committed_watch";
    public const string RollingBack = "rolling_back";

    public const string PostCommitRollback = "post_commit_rollback";
    public const string RollbackFailed = "rollback_failed";
    public const string PostCommitUnhealthy = "post_commit_unhealthy";
    public const string WatchUnavailable = "watch_unavailable";
    public const string LkgPromotionFailed = "lkg_promotion_failed";
    public const string LkgBelowFloor = "lkg_below_floor";
    public const string UnknownPhaseAlert = "watch_unknown_phase";
}
