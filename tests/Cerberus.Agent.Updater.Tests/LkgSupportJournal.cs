using System.IO;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater.Tests;

// The host transitions use their production CAS delegates and serializer. Only acquisition of the
// SYSTEM-owned global journal lock is outside this disposable, single-writer fixture.
internal sealed class LkgSupportJournal(string root)
{
    public AgentUpdateJournalStore Store { get; } = new(root);

    public AgentUpdateJournal Read() => Store.Read();

    public AgentUpdateJournal Change(Func<AgentUpdateJournal, AgentUpdateJournal> patch)
    {
        var prior = Read();
        var next = patch(prior);
        if (ReferenceEquals(prior, next)) return prior;
        next = next with { Revision = prior.Revision + 1 };
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, next);
        return next;
    }
}
