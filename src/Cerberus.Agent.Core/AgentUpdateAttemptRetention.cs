namespace Cerberus.Agent.Core;

/// <summary>
/// Frees disk held by finished update attempts. Only the downloaded installer and the runner copy of the
/// installed binaries are removed; the attempt folder, its JSON records and the runner inventory stay as
/// evidence. The active attempt and the newest finished attempts keep their payload. Links are never followed.
/// Callers hold the service update gate, so no stage or apply runs concurrently.
/// </summary>
public static class AgentUpdateAttemptRetention
{
    public const int DefaultKeepNewestFinished = 2;
    private const string RunnerInventoryFileName = "inventory.json";

    private static readonly EnumerationOptions NoLinks = new()
    {
        RecurseSubdirectories = true,
        AttributesToSkip = FileAttributes.ReparsePoint,
        IgnoreInaccessible = false,
    };

    /// <summary>Returns how many attempt folders had payload removed. Never throws; an unprunable folder is skipped.</summary>
    public static int PrunePayloads(string root, AgentUpdateJournal active, int keepNewestFinished = DefaultKeepNewestFinished)
    {
        if (active.HasUnfinishedAttempt)
            return 0;
        try
        {
            var fullRoot = AgentUpdateSecurity.NormalizeRoot(root);
            var attemptsRoot = Path.Combine(fullRoot, "attempts");
            if (!Directory.Exists(attemptsRoot))
                return 0;
            var finished = Directory.EnumerateDirectories(attemptsRoot, AgentUpdateSecurity.AttemptDirectoryPrefix + "*")
                .Select(path => Path.GetFileName(path)[AgentUpdateSecurity.AttemptDirectoryPrefix.Length..])
                .Where(id => AgentUpdateSecurity.IsSafeAttemptId(id) && id != active.AttemptId)
                .OrderByDescending(id => Directory.GetCreationTimeUtc(Path.Combine(attemptsRoot, AgentUpdateSecurity.AttemptDirectoryPrefix + id)))
                .Skip(Math.Max(0, keepNewestFinished))
                .ToList();
            var pruned = 0;
            foreach (var id in finished)
                if (TryPrunePayload(fullRoot, id))
                    pruned++;
            return pruned;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return 0;
        }
    }

    private static bool TryPrunePayload(string root, string attemptId)
    {
        var removed = false;
        try
        {
            var directory = AgentUpdateSecurity.ResolveAttemptDirectory(root, attemptId);
            if (IsLink(directory))
                return false;
            var artifact = Path.Combine(directory, AgentUpdateSecurity.ArtifactFileName);
            if (File.Exists(artifact) && !IsLink(artifact))
            {
                AgentUpdateSecurity.ValidateTrustedPath(artifact, directory, allowMissing: false);
                File.Delete(artifact);
                removed = true;
            }
            var runner = Path.Combine(directory, AgentUpdateRunnerFiles.RunnerDirectoryName);
            if (!Directory.Exists(runner) || IsLink(runner))
                return removed;
            AgentUpdateSecurity.ValidateTrustedPath(runner, directory, allowMissing: false);
            var inventory = Path.Combine(runner, RunnerInventoryFileName);
            foreach (var file in Directory.EnumerateFiles(runner, "*", NoLinks).ToList())
            {
                if (string.Equals(file, inventory, StringComparison.OrdinalIgnoreCase))
                    continue;
                File.Delete(file);
                removed = true;
            }
            foreach (var child in Directory.EnumerateDirectories(runner, "*", NoLinks).OrderByDescending(path => path.Length).ToList())
                if (!Directory.EnumerateFileSystemEntries(child).Any())
                    Directory.Delete(child);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            // Keep whatever is left; the next tick retries.
        }
        return removed;
    }

    private static bool IsLink(string path)
        => (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
}
