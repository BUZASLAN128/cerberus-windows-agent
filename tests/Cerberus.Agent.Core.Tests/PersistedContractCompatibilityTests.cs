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
        var previousPhases = Previous("journal_phases").ToArray();
        var admittedPhases = previousPhases.Concat(additions.Select(x => x.Name)).ToHashSet(StringComparer.Ordinal);
        var sources = Directory.EnumerateFiles(Path.Combine(repo, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Split(Path.DirectorySeparatorChar).Any(part => part is "bin" or "obj"));
        var schema = new Regex("\"((?:agent|cerberus)\\.[a-z0-9_.-]+\\.v[0-9]+)\"");
        var observedSchemas = sources.SelectMany(file => schema.Matches(File.ReadAllText(file)).Select(match => match.Groups[1].Value))
            .Distinct(StringComparer.Ordinal);
        Assert.DoesNotContain(observedSchemas, value => !admittedSchemas.Contains(value));

        var journalFile = sources.Single(file => Path.GetFileName(file) == "AgentUpdateJournal.cs");
        var phaseBlock = Regex.Match(File.ReadAllText(journalFile), @"\bKnownPhase\(string phase\)\s*=>\s*phase\s+is\s+(?<body>[^;]+);");
        Assert.True(phaseBlock.Success);
        var operands = Regex.Split(phaseBlock.Groups["body"].Value.Trim(), @"\s+or\s+");
        var observedPhases = operands.Select(ResolvePhaseOperand).ToArray();
        Assert.Equal(operands.Length, observedPhases.Length);
        var observedSet = observedPhases.ToHashSet(StringComparer.Ordinal);
        Assert.All(previousPhases, phase => Assert.Contains(phase, observedSet));
        Assert.DoesNotContain(observedPhases, value => !admittedPhases.Contains(value));

        IEnumerable<string> Previous(string key) => previous.GetProperty(key).EnumerateArray().Select(x => x.GetString()!);
    }

    [Fact]
    public void UnresolvedKnownPhaseOperandFailsWithTheSymbolName()
    {
        const string operand = "AgentUpdaterContract.UnknownPhase";
        var error = Assert.Throws<Xunit.Sdk.TrueException>(() => ResolvePhaseOperand(operand));
        Assert.Contains(operand, error.Message);
    }

    private static string ResolvePhaseOperand(string operand)
    {
        if (operand.StartsWith('"') && operand.EndsWith('"'))
            return JsonSerializer.Deserialize<string>(operand)!;

        var symbol = operand.Split('.');
        var journalType = typeof(AgentUpdateJournalStore);
        var type = symbol.Length == 2 ? journalType.Assembly.GetType($"{journalType.Namespace}.{symbol[0]}") : null;
        var field = type?.GetField(symbol[1], BindingFlags.Public | BindingFlags.Static);
        var phase = field is { IsLiteral: true } && field.FieldType == typeof(string)
            ? field.GetRawConstantValue() as string
            : null;
        Assert.True(phase is not null, $"Unresolved KnownPhase operand '{operand}'. Expected a public const string or a string literal.");
        return phase!;
    }
}
