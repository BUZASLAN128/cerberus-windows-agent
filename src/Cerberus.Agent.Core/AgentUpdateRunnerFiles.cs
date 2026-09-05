using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

public static class AgentUpdateRunnerFiles
{
    public const string RunnerDirectoryName = "runner";
    private sealed record Inventory(IReadOnlyDictionary<string, string> Files);

    /// <summary>Freeze the installed runner and its complete executable dependency tree outside the MSI-owned directory.</summary>
    public static string Prepare(string runtimeDirectory, string attemptDirectory)
    {
        AgentUpdateSecurity.ValidateTrustedPath(runtimeDirectory, Path.GetPathRoot(runtimeDirectory)!, allowMissing: false);
        var destination = Path.Combine(attemptDirectory, RunnerDirectoryName);
        if (Directory.Exists(destination))
        {
            Validate(destination, attemptDirectory);
            return Path.Combine(destination, "Cerberus.Agent.Updater.exe");
        }
        Directory.CreateDirectory(destination);
        AgentUpdateSecurity.EnsureProtectedRoot(destination);
        var inventory = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in Directory.EnumerateFiles(runtimeDirectory, "*", SearchOption.AllDirectories))
        {
            var name = Path.GetFileName(source);
            if (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                !name.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase) &&
                !name.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase))
                continue;
            AgentUpdateSecurity.ValidateTrustedPath(source, runtimeDirectory, allowMissing: false);
            var relative = Path.GetRelativePath(runtimeDirectory, source);
            var target = Path.Combine(destination, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            AgentUpdateSecurity.ValidateTrustedPath(target, destination, allowMissing: true);
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
        AgentUpdateDurableFile.Write(Path.Combine(destination, "inventory.json"), destination, new Inventory(inventory));
        Validate(destination, attemptDirectory);
        return Path.Combine(destination, "Cerberus.Agent.Updater.exe");
    }

    public static void Validate(string runnerDirectory, string attemptDirectory)
    {
        AgentUpdateSecurity.ValidateTrustedPath(runnerDirectory, attemptDirectory, allowMissing: false);
        var inventory = AgentUpdateDurableFile.Read<Inventory>(Path.Combine(runnerDirectory, "inventory.json"), runnerDirectory)
            ?? throw new InvalidOperationException("Update runner inventory is missing.");
        if (inventory.Files.Count is < 2 or > 4096)
            throw new InvalidOperationException("Update runner inventory is invalid.");
        foreach (var (relative, expected) in inventory.Files)
        {
            var path = Path.GetFullPath(Path.Combine(runnerDirectory, relative));
            AgentUpdateSecurity.ValidateTrustedPath(path, runnerDirectory, allowMissing: false);
            using var stream = File.OpenRead(path);
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(stream)), expected, StringComparison.Ordinal))
                throw new InvalidOperationException("Update runner dependency changed.");
        }
    }
}
