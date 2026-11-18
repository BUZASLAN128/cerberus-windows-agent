using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class PersistedContractCompatibilityTests
{
    [Fact]
    public void PersistedSchemaAndJournalPhaseChangesAreAccountedFor()
    {
        var repo = ServerPackageStaticTests.FindRepoRoot();
        using var fixture = JsonDocument.Parse(File.ReadAllText(Path.Combine(repo, "tests", "fixtures", "persisted-contract.previous-release.json")));
        var previous = fixture.RootElement.GetProperty("readable_by_previous_release");
        var additions = fixture.RootElement.GetProperty("read_only_additions").EnumerateObject().ToArray();
        Assert.All(additions, entry => Assert.False(string.IsNullOrWhiteSpace(entry.Value.GetString())));
        var admittedSchemas = Previous("schemas").Concat(additions.Select(x => x.Name)).ToHashSet(StringComparer.Ordinal);
        var admittedPhases = Previous("journal_phases").Concat(additions.Select(x => x.Name)).ToHashSet(StringComparer.Ordinal);
        var sources = Directory.EnumerateFiles(Path.Combine(repo, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Split(Path.DirectorySeparatorChar).Any(part => part is "bin" or "obj"));
        var schema = new Regex("\"((?:agent|cerberus)\\.[a-z0-9_.-]+\\.v[0-9]+)\"");
        var observedSchemas = sources.SelectMany(file => schema.Matches(File.ReadAllText(file)).Select(match => match.Groups[1].Value))
            .Distinct(StringComparer.Ordinal);
        Assert.DoesNotContain(observedSchemas, value => !admittedSchemas.Contains(value));

        var journalFile = sources.Single(file => Path.GetFileName(file) == "AgentUpdateJournal.cs");
        var constants = typeof(AgentUpdateStates).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .ToDictionary(field => field.Name, field => (string)field.GetRawConstantValue()!, StringComparer.Ordinal);
        var phaseBlock = Regex.Match(File.ReadAllText(journalFile), @"\bKnownPhase\(string phase\)\s*=>\s*(?<body>[^;]+);");
        Assert.True(phaseBlock.Success);
        var observedPhases = Regex.Matches(phaseBlock.Groups["body"].Value, "AgentUpdateStates\\.(?<constant>\\w+)|\"(?<literal>[a-z_]+)\"")
            .Select(match => match.Groups["constant"].Success ? constants[match.Groups["constant"].Value] : match.Groups["literal"].Value);
        Assert.DoesNotContain(observedPhases, value => !admittedPhases.Contains(value));

        IEnumerable<string> Previous(string key) => previous.GetProperty(key).EnumerateArray().Select(x => x.GetString()!);
    }
}
