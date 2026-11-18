using System.Globalization;

namespace Cerberus.Agent.Core;

/// <summary>Constructs the fixed argv for the protected LKG MSI.</summary>
internal static class AgentUpdateRollbackCommand
{
    public static IReadOnlyList<string> Arguments(string updatesRoot, string rollbackAttemptId, DateTimeOffset now)
    {
        if (!AgentUpdateSecurity.IsSafeAttemptId(rollbackAttemptId))
            throw new ArgumentException("Rollback attempt identifier is invalid.", nameof(rollbackAttemptId));
        var store = new AgentUpdateLkgStore(updatesRoot);
        var timestamp = now.UtcDateTime.ToString("yyyyMMddTHHmmssfffffffZ", CultureInfo.InvariantCulture);
        return ["/i", store.MsiPath, "/qn", "/norestart", "CERBERUS_EULA_ACCEPTED=1",
            "CERBERUS_UPDATE_REQUIRE_BACKEND=0", $"CERBERUS_ROLLBACK_ATTEMPT={rollbackAttemptId}", "REINSTALLMODE=amus",
            "/l*v", Path.Combine(store.UpdatesRoot, "logs", $"msiexec-rollback-{timestamp}.log")];
    }
}
