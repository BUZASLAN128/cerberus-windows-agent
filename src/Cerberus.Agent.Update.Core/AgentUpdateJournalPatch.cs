namespace Cerberus.Agent.Core;

internal static class AgentUpdateJournalPatch
{
    private const int RetryLimit = 3;

    /// <summary>
    /// Applies a host transition only while its forward attempt and phase still match.
    /// The callback runs under the journal lock, can run again on an I/O retry, and may return null to decline the write.
    /// </summary>
    public static bool TryApply(AgentUpdateJournalStore store, string attemptId, string expectedPhase,
        Func<AgentUpdateJournal, AgentUpdateJournal?> patch)
        => TryApply(store.Change, attemptId, expectedPhase, patch);

    internal static bool TryApply(Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        string attemptId, string expectedPhase, Func<AgentUpdateJournal, AgentUpdateJournal?> patch)
    {
        if (!AgentUpdateSecurity.IsSafeAttemptId(attemptId))
            throw new ArgumentException("Update attempt identifier is invalid.", nameof(attemptId));

        for (var retry = 0; ; retry++)
        {
            try
            {
                change(before =>
                {
                    if (before.AttemptId != attemptId || before.Phase != expectedPhase || patch(before) is not { } after)
                        throw new JournalChangedException();
                    if (after.AttemptId != attemptId)
                        throw new InvalidOperationException("A host journal patch cannot change the forward attempt.");
                    return after with { Extra = before.Extra };
                });
                return true;
            }
            catch (JournalChangedException) { return false; }
            catch (IOException) when (retry < RetryLimit)
            {
                Thread.Sleep((25 << retry) + Random.Shared.Next(25));
            }
        }
    }

    private sealed class JournalChangedException : Exception;
}
