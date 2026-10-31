namespace Cerberus.Agent.Core;

public sealed partial class CommandReplayStore
{
    /// <summary>A record ends its retention at <c>expires_at + 24 h</c>; the outbox stops then too.</summary>
    private static List<CommandReplayRecord> Purge(IEnumerable<CommandReplayRecord> records, long now)
        => records.Where(r => now <= r.ExpiresAt + RetentionSeconds).ToList();

    /// <summary>Only records past their window and without a pending result may make room.</summary>
    private static bool IsEvictable(CommandReplayRecord record, long now)
        => now > record.ExpiresAt + CommandEnvelopeVerifier.SkewSeconds && !record.HasPendingResult;

    /// <summary>Result bytes never submitted for an agent id other than the current one can no longer be delivered.</summary>
    private static List<CommandReplayRecord> DropForeignPending(List<CommandReplayRecord> records, string agentId)
        => records.Any(r => r.ResultB64 is not null && !r.ResultSubmitted && !string.Equals(r.AgentId, agentId, StringComparison.Ordinal))
            ? records.Select(r => r.ResultB64 is not null && !r.ResultSubmitted && !string.Equals(r.AgentId, agentId, StringComparison.Ordinal)
                ? r with { ResultB64 = null }
                : r).ToList()
            : records;

}
