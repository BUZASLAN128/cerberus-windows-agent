using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

public static class AgentUpdateRunnerFiles
{
    public const string RunnerDirectoryName = "runner";
    private sealed record Inventory(IReadOnlyDictionary<string, string> Files, string? SourceDirectory = null);

    /// <summary>Freeze the installed runner and its complete executable dependency tree outside the MSI-owned directory.</summary>
    public static string Prepare(string runtimeDirectory, string attemptDirectory)
    {
        AgentUpdateSecurity.ValidateProtectedTree(attemptDirectory);
        AgentUpdateSecurity.ValidateInstalledSource(runtimeDirectory, runtimeDirectory);
        var destination = Path.Combine(attemptDirectory, RunnerDirectoryName);
        if (Directory.Exists(destination))
        {
            ValidateForLaunch(runtimeDirectory, attemptDirectory);
            return Path.Combine(destination, "Cerberus.Agent.Updater.exe");
        }
        AgentUpdateSecurity.EnsureProtectedRoot(destination);
        var inventory = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in EnumerateInstalledSourceFiles(runtimeDirectory))
        {
            var relative = Path.GetRelativePath(runtimeDirectory, source);
            var target = Path.Combine(destination, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            AgentUpdateSecurity.ValidateProtectedPath(target, destination, allowMissing: true);
            using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
            var digest = Convert.ToHexString(SHA256.HashData(input));
            input.Position = 0;
            using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
            {
                input.CopyTo(output);
                output.Flush(flushToDisk: true);
            }
            using var copied = File.OpenRead(target);
            if (digest != Convert.ToHexString(SHA256.HashData(copied)))
                throw new InvalidOperationException("Update runner dependency checksum mismatch.");
            inventory.Add(relative, digest);
        }
        if (!inventory.ContainsKey("Cerberus.Agent.Updater.exe") || !inventory.ContainsKey("Cerberus.Agent.Core.dll"))
            throw new InvalidOperationException("Installed update runner dependencies are incomplete.");
        AgentUpdateDurableFile.Write(Path.Combine(destination, "inventory.json"), destination, new Inventory(inventory, AgentUpdateSecurity.NormalizeRoot(runtimeDirectory)));
        ValidateForLaunch(runtimeDirectory, attemptDirectory);
        return Path.Combine(destination, "Cerberus.Agent.Updater.exe");
    }

    public static void Validate(string runnerDirectory, string attemptDirectory)
    {
        AgentUpdateSecurity.ValidateProtectedPath(runnerDirectory, attemptDirectory, allowMissing: false);
        AgentUpdateSecurity.ValidateProtectedTree(runnerDirectory);
        var inventory = AgentUpdateDurableFile.Read<Inventory>(Path.Combine(runnerDirectory, "inventory.json"), runnerDirectory)
            ?? throw new InvalidOperationException("Update runner inventory is missing.");
        if (inventory.Files.Count is < 2 or > 4096 ||
            !inventory.Files.ContainsKey("Cerberus.Agent.Updater.exe") || !inventory.Files.ContainsKey("Cerberus.Agent.Core.dll"))
            throw new InvalidOperationException("Update runner inventory is invalid.");
        foreach (var (relative, expected) in inventory.Files)
        {
            var path = Path.GetFullPath(Path.Combine(runnerDirectory, relative));
            AgentUpdateSecurity.ValidateProtectedPath(path, runnerDirectory, allowMissing: false);
            using var stream = File.OpenRead(path);
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(stream)), expected, StringComparison.Ordinal))
                throw new InvalidOperationException("Update runner dependency changed.");
        }
        if (Directory.EnumerateFiles(runnerDirectory, "*", SearchOption.AllDirectories).Count() != inventory.Files.Count + 1)
            throw new InvalidOperationException("Update runner contains an unbound file.");
    }

    /// <summary>The service checks the copied bytes against the trusted installed source before it executes any copied code.</summary>
    public static void ValidateForLaunch(string runtimeDirectory, string attemptDirectory)
    {
        var runnerDirectory = Path.Combine(attemptDirectory, RunnerDirectoryName);
        Validate(runnerDirectory, attemptDirectory);
        AgentUpdateSecurity.ValidateInstalledSource(runtimeDirectory, runtimeDirectory);
        var inventory = AgentUpdateDurableFile.Read<Inventory>(Path.Combine(runnerDirectory, "inventory.json"), runnerDirectory)!;
        if (!string.Equals(inventory.SourceDirectory, AgentUpdateSecurity.NormalizeRoot(runtimeDirectory), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update runner source binding is invalid.");
        var sourceFiles = EnumerateInstalledSourceFiles(runtimeDirectory).ToArray();
        if (sourceFiles.Length != inventory.Files.Count)
            throw new InvalidOperationException("Update runner source dependency set changed.");
        foreach (var source in sourceFiles)
        {
            AgentUpdateSecurity.ValidateInstalledSource(source, runtimeDirectory);
            var relative = Path.GetRelativePath(runtimeDirectory, source);
            using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!inventory.Files.TryGetValue(relative, out var expected) || Convert.ToHexString(SHA256.HashData(input)) != expected)
                throw new InvalidOperationException("Update runner does not match its trusted installed source.");
        }
    }

    private static IEnumerable<string> EnumerateInstalledSourceFiles(string runtimeDirectory)
    {
        var pending = new Stack<string>();
        pending.Push(runtimeDirectory);
        var entries = 0;
        var files = 0;
        while (pending.TryPop(out var directory))
        {
            // Validate before enumeration so a source junction is never followed, including empty directories.
            AgentUpdateSecurity.ValidateInstalledSource(directory, runtimeDirectory);
            foreach (var path in Directory.EnumerateFileSystemEntries(directory))
            {
                if (++entries > 65536) throw new InvalidOperationException("Installed update source exceeds inventory bounds.");
                AgentUpdateSecurity.ValidateInstalledSource(path, runtimeDirectory);
                if (Directory.Exists(path))
                {
                    pending.Push(path);
                    continue;
                }
                if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                    !path.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase) && !path.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (++files > 4096) throw new InvalidOperationException("Installed update source exceeds dependency bounds.");
                yield return path;
            }
        }
    }
}
