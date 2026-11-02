namespace Cerberus.Agent.Core;

public sealed partial class CommandReplayStore
{
    /// <summary>Commit a bound ordinary refusal atomically before its terminal negative ACK.</summary>
    internal ReplayReserveOutcome TryRejectNew(CommandReplayRecord record)
        => TryInsert(record, rejection: true);

    private ReplayReserveOutcome TryInsert(CommandReplayRecord record, bool rejection)
    {
        ArgumentNullException.ThrowIfNull(record);
        lock (_gate)
        {
            if (rejection && (record.Type == EnvelopeTypes.AgentState || !IsValid(record) ||
                record.State != EnvelopeRecordStates.RejectedAfterReserve ||
                string.IsNullOrWhiteSpace(record.RejectReason) || record.RejectReason.Length > 64 ||
                record.ResultB64 is not null || record.ResultSubmitted))
                return ReplayReserveOutcome.Unavailable;
            if (!EnsureLoaded() || _records.Any(r => Same(r, record.AgentId, record.Id)))
                return ReplayReserveOutcome.Unavailable;

            var now = NowUnix();
            var next = DropForeignPending(Purge(_records, now), record.AgentId);
            var exempt = record.Type == EnvelopeTypes.AgentState;
            if (!exempt && next.Count >= MaxRecords)
            {
                var evictable = next.Where(r => IsEvictable(r, now))
                    .OrderBy(r => r.ExpiresAt).ThenBy(r => r.Id, StringComparer.Ordinal)
                    .Take(next.Count - MaxRecords + 1).ToHashSet();
                next = next.Where(r => !evictable.Contains(r)).ToList();
                if (next.Count >= MaxRecords) return ReplayReserveOutcome.Full;
            }

            var unsubmitted = exempt || rejection ? 0 : next.Where(r => !r.ResultSubmitted &&
                string.Equals(r.AgentId, record.AgentId, StringComparison.Ordinal)).Sum(r => ExposureBytes(r, now));
            // A refusal cannot produce a result; it still obeys record-count and serialized-file bounds.
            if (!exempt && !rejection && unsubmitted + EnvelopeExecutionQueue.MaxResultBodyBytes > MaxUnsubmittedResultBytes)
                return ReplayReserveOutcome.Full;

            next.Add(rejection ? record : record with { State = EnvelopeRecordStates.Reserved });
            return Commit(next) ? ReplayReserveOutcome.Reserved : ReplayReserveOutcome.Unavailable;
        }
    }
}
