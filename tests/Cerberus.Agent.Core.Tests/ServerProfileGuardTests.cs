// Repository-shape guards for the server-profile pilot: no product-name leakage into the public
// agent repo, no new oversized source files and no growth of the already oversized ones.
// The server command registry itself is covered by AgentCommandRegistryTests.
namespace Cerberus.Agent.Core.Tests;

public sealed class ServerProfileGuardTests
{
    // SHA-256 (lowercase hex) of the forbidden lowercase ASCII token and its length. The token itself is
    // never stored; every window of that length over a lowercased path or text is hashed and compared.
    private const string ForbiddenSha256 = "85042de372b88669331daa0aaf6286cbf2a3078324696f28e3cfee3737e07771";
    private const int ForbiddenLength = 6;

    private static readonly string[] SkippedDirs = { "out", ".git", "node_modules", ".vs" };

    // Build outputs such as bin, obj and bin-fix-d.
    private static readonly string[] SkippedDirPrefixes = { "bin", "obj" };

    private static readonly string[] TextExtensions =
    {
        ".cs", ".ps1", ".md", ".yml", ".yaml", ".csproj", ".resx", ".json", ".xaml", ".wxl", ".wxs",
        ".wixproj", ".slnx", ".props", ".targets", ".manifest", ".rtf", ".b64", ".txt", ".gitignore", ".sh",
    };

    private static readonly string[] TextNames = { "CODEOWNERS", "LICENSE" };

    // Oversized source files that already existed before the pilot, with their dev line counts.
    // Growth is not allowed; shrinking is.
    private static readonly Dictionary<string, int> LineCaps = new(StringComparer.Ordinal)
    {
        ["src/Cerberus.Agent.Core/AgentApiClient.cs"] = 676,
        ["src/Cerberus.Agent.App/ServiceMode.cs"] = 538,
        ["src/Cerberus.Agent.Core/AgentLifecycleState.cs"] = 645,
        ["src/Cerberus.Agent.App/Updates/AgentUpdateLocalService.cs"] = 1453,
    };

    // Other source files that were already at 500 lines or more before the pilot.
    private static readonly HashSet<string> PreExistingOversized = new(StringComparer.Ordinal)
    {
        "scripts/live-service-acceptance.ps1",
        "src/Cerberus.Agent.App/MainWindow.xaml.cs",
        "src/Cerberus.Agent.App/TrayHost.cs",
        "src/Cerberus.Agent.Core/AgentUpdateStager.cs",
        "src/Cerberus.Agent.Core/AgentUpdateState.cs",
        "src/Cerberus.Agent.Integrations.Ad/LocalUserCommandHandlers.Support.cs",
        "src/Cerberus.Agent.Integrations.Ad/LocalUserCommandHandlers.cs",
        "tests/Cerberus.Agent.Core.Tests/AgentLifecycleControlTests.cs",
        "tests/Cerberus.Agent.Core.Tests/AgentServiceCredentialBridgeTests.cs",
        "tests/Cerberus.Agent.Core.Tests/AgentUpdateDurabilityTests.cs",
        "tests/Cerberus.Agent.Core.Tests/AgentUpdateStagerTests.cs",
        "tests/Cerberus.Agent.Core.Tests/AgentUxStaticTests.cs",
        "tests/Cerberus.Agent.Core.Tests/LocalUserCommandHandlersTests.cs",
    };

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Cerberus.WindowsAgent.slnx")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static IEnumerable<string> Files(string root, Func<string, bool> include)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            foreach (var sub in Directory.GetDirectories(current))
            {
                var name = Path.GetFileName(sub);
                if (!SkippedDirs.Contains(name, StringComparer.OrdinalIgnoreCase)
                    && !SkippedDirPrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                {
                    pending.Push(sub);
                }
            }

            foreach (var file in Directory.GetFiles(current))
            {
                if (include(file))
                {
                    yield return file;
                }
            }
        }
    }

    private static string Rel(string root, string file) =>
        Path.GetRelativePath(root, file).Replace('\\', '/');

    private static bool IsText(string file) =>
        TextExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase)
        || TextNames.Contains(Path.GetFileName(file), StringComparer.Ordinal);

    private static bool ContainsForbidden(string text)
    {
        Span<byte> window = stackalloc byte[ForbiddenLength];
        Span<byte> digest = stackalloc byte[32];
        var run = 0;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c >= 'A' && c <= 'Z')
            {
                c = (char)(c + 32);
            }

            if (c < 'a' || c > 'z')
            {
                run = 0;
                continue;
            }

            if (++run < ForbiddenLength)
            {
                continue;
            }

            for (var k = 0; k < ForbiddenLength; k++)
            {
                var ch = text[i - ForbiddenLength + 1 + k];
                window[k] = (byte)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
            }

            System.Security.Cryptography.SHA256.HashData(window, digest);
            if (Convert.ToHexString(digest).Equals(ForbiddenSha256, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    [Fact]
    public void NoTrackedTextFileOrPathMentionsTheOtherProduct()
    {
        var root = RepoRoot();
        var hits = new List<string>();
        foreach (var file in Files(root, f => true))
        {
            var rel = Rel(root, file);
            if (ContainsForbidden(rel))
            {
                hits.Add(rel + " (path)");
                continue;
            }

            if (IsText(file) && ContainsForbidden(File.ReadAllText(file)))
            {
                hits.Add(rel);
            }
        }

        Assert.True(hits.Count == 0, "Forbidden product name found in file: " + string.Join(", ", hits));
    }

    [Fact]
    public void SourceFilesStayUnderLimitAndOversizedOnesDoNotGrow()
    {
        var root = RepoRoot();
        var problems = new List<string>();
        foreach (var file in Files(root, f => f.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
                                              || f.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)))
        {
            var rel = Rel(root, file);
            var lines = File.ReadAllLines(file).Length;
            if (LineCaps.TryGetValue(rel, out var cap))
            {
                if (lines > cap)
                {
                    problems.Add($"{rel}: {lines} lines > dev {cap}");
                }
            }
            else if (lines >= 500 && !PreExistingOversized.Contains(rel))
            {
                problems.Add($"{rel}: {lines} lines (new file must stay under 500)");
            }
        }

        foreach (var capped in LineCaps.Keys)
        {
            Assert.True(File.Exists(Path.Combine(root, capped)), "Capped file missing: " + capped);
        }

        Assert.True(problems.Count == 0, string.Join("; ", problems));
    }
}
