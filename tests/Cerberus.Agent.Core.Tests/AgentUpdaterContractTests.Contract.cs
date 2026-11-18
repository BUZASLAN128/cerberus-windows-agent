using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentUpdaterContractTests
{
    [Fact]
    public void FrozenSet_Snapshot()
    {
        Assert.Equal("--attempt", AgentUpdaterContract.AttemptArgument);
        Assert.Equal("agent.update.plan.v2", AgentUpdaterContract.PlanSchema);
        Assert.Equal("agent.update.journal.v1", new AgentUpdateJournal().SchemaVersion);
        Assert.Equal("agent.update.state.v1", AgentUpdateState.CurrentSchemaVersion);
        Assert.Equal("agent.update.installer_result.v1", AgentUpdateInstallerResult.CurrentSchemaVersion);
        Assert.Equal("agent.update.manifest.v1", AgentUpdateManifest.V1SchemaVersion);
        Assert.Equal("agent.update.manifest.v2", AgentUpdateManifest.V2SchemaVersion);
        Assert.Equal("cerberus-agent-lifecycle.v1", AgentLifecycleFile.SchemaVersion);

        var journalSource = ReadSource("Cerberus.Agent.Update.Core", "AgentUpdateJournal.cs");
        var knownPhaseBody = Regex.Match(journalSource, @"internal static bool KnownPhase\([^)]*\) => (?<body>[^;]+);");
        Assert.True(knownPhaseBody.Success);
        var phases = ConstantsOf(typeof(AgentUpdateStates))
            .Concat(ConstantsOf(typeof(AgentUpdaterContract)))
            .Concat(Regex.Matches(knownPhaseBody.Groups["body"].Value, "\"([^\"]+)\"")
                .Select(match => match.Groups[1].Value))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            "available awaiting_consent blocked checking current downloading failed health_pending install_may_have_started " +
            "installed installing launch_requested not_checked pending_reboot quarantined recovery_required retryable_busy staged",
            string.Join(" ", phases.Where(AgentUpdateJournalStore.KnownPhase)));

        var root = Path.Combine(Path.GetTempPath(), "cerberus-contract-snapshot-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = Path.Combine(root, "transaction.json");
            var journal = new AgentUpdateJournal();
            var store = new AgentUpdateJournalStore(root);
            bool Accepts(AgentUpdateJournal value)
            {
                AgentUpdateDurableFile.Write(path, root, value);
                try { _ = store.Read(); return true; }
                catch (InvalidOperationException ex) when (ex.Message == "Update journal is invalid.") { return false; }
            }

            var snapshot = new AgentUpdateReconciliationSnapshot(AgentUpdateStates.Staged, 0, false, false, null, 0, null, null);
            Assert.Equal("available awaiting_consent checking downloading retryable_busy staged",
                string.Join(" ", phases.Where(phase => Accepts(journal with { ReconciliationSnapshot = snapshot with { Phase = phase } }))));
            var request = new AgentUpdateInstallRequest(DateTimeOffset.UnixEpoch, 0, DateTimeOffset.UnixEpoch.AddMinutes(1));
            var probes = new[] { -1, 0, 1, 2, 3, 4, int.MaxValue };
            Assert.Equal(new[] { 0, 1, 2, 3 }, probes.Where(count => Accepts(journal with { RetryCount = count })));
            Assert.Equal(new[] { 0, 1, 2, 3 }, probes.Where(count =>
                Accepts(journal with { ReconciliationSnapshot = snapshot with { RetryCount = count } })));
            Assert.Equal(new[] { 0, 1, 2, 3 }, probes.Where(count => (request with { Attempts = count }).IsValid()));

            var requestSource = ReadSource("Cerberus.Agent.Update.Core", "AgentUpdateInstallRequest.cs");
            var terminalReasonBody = Regex.Match(requestSource, @"TerminalUtc is not null && TerminalReason is(?<body>[^;]+);");
            Assert.True(terminalReasonBody.Success);
            var reasons = Regex.Matches(terminalReasonBody.Groups["body"].Value, "\"([^\"]+)\"")
                .Select(match => match.Groups[1].Value)
                .Where(reason => (request with { TerminalReason = reason, TerminalUtc = DateTimeOffset.UnixEpoch }).IsValid())
                .Order(StringComparer.Ordinal);
            Assert.Equal(
                "attempt_failed automatic_updates_disabled current expired installed lifecycle_changed plan_mismatch release_unavailable staging_failed superseded",
                string.Join(" ", reasons));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        var codes = ConstantsOf(typeof(AgentUpdateErrorCodes)).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(
            "artifact_too_large artifact_url_denied channel_mismatch download_failed hash_mismatch installer_busy manifest_expired " +
            "manifest_invalid manifest_unavailable msi_failed not_configured reboot_required recovery_timeout retry_exhausted " +
            "signature_invalid staging_failed uac_cancelled unknown",
            string.Join(" ", codes));
        Assert.All(codes, code => Assert.True(AgentUpdateErrorCodes.IsCode(code)));
        Assert.True(AgentUpdateErrorCodes.IsCode(new string('a', 64)));
        Assert.False(AgentUpdateErrorCodes.IsCode(new string('a', 65)));
        Assert.False(AgentUpdateErrorCodes.IsCode(""));
        Assert.False(AgentUpdateErrorCodes.IsCode("not-a_code"));
        Assert.False(AgentUpdateErrorCodes.IsCode("Uppercase"));
        Assert.False(AgentUpdateErrorCodes.IsCode("code1"));

        var signedShape = new AgentUpdateExpectedPlan("1.2.3", "dev:1", new string('a', 64));
        using var signedJson = JsonDocument.Parse(JsonSerializer.Serialize(signedShape));
        Assert.Equal(new[] { "artifact_sha256", "release_id", "version" },
            signedJson.RootElement.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
        Assert.Equal(JsonUnmappedMemberHandling.Disallow,
            typeof(AgentUpdateExpectedPlan).GetCustomAttribute<JsonUnmappedMemberHandlingAttribute>()!.UnmappedMemberHandling);
        Assert.True(signedShape.IsValid());
        Assert.True((signedShape with { Version = new string('v', 50), ReleaseId = new string('r', 128) }).IsValid());
        Assert.False((signedShape with { Version = new string('v', 51) }).IsValid());
        Assert.False((signedShape with { ReleaseId = new string('r', 129) }).IsValid());
        Assert.False((signedShape with { ArtifactSha256 = new string('a', 65) }).IsValid());
    }

    [Fact]
    public void UpdateCore_ReferencesNoAgentAssembly()
        => Assert.DoesNotContain(typeof(AgentUpdaterContract).Assembly.GetReferencedAssemblies(),
            assembly => assembly.Name!.StartsWith("Cerberus.", StringComparison.Ordinal));

    [Fact]
    public void UpdaterProject_ReferencesAndLabSeamAreMirrored()
    {
        var updater = XDocument.Parse(ReadSource("Cerberus.Agent.Updater", "Cerberus.Agent.Updater.csproj"));
        var references = updater.Descendants("ProjectReference").ToArray();
        Assert.Equal(2, references.Length);
        var unconditional = Assert.Single(references.Where(reference => reference.Attribute("Condition") is null));
        Assert.Equal(@"..\Cerberus.Agent.Update.Core\Cerberus.Agent.Update.Core.csproj", (string?)unconditional.Attribute("Include"));
        var lab = Assert.Single(references.Where(reference => reference.Attribute("Condition") is not null));
        Assert.Equal(@"..\Cerberus.Agent.Runtime\Cerberus.Agent.Runtime.csproj", (string?)lab.Attribute("Include"));
        Assert.Equal("'$(AgentUpdateLabPolicyB64)' != ''", (string?)lab.Attribute("Condition"));

        var removes = updater.Descendants("Compile").ToDictionary(node => (string)node.Attribute("Remove")!);
        Assert.Equal("'$(AgentUpdateLabPolicyB64)' == ''", (string?)removes["UpdaterLab.Runtime.cs"].Attribute("Condition"));
        Assert.Equal("'$(AgentUpdateLabPolicyB64)' != ''", (string?)removes["UpdaterLab.Release.cs"].Attribute("Condition"));
        var updateCore = XDocument.Parse(ReadSource("Cerberus.Agent.Update.Core", "Cerberus.Agent.Update.Core.csproj"));
        Assert.Empty(updateCore.Descendants("PackageReference"));
        Assert.Empty(updateCore.Descendants("ProjectReference"));
    }

    [Fact]
    public void GoldenContractValues()
    {
        Assert.Equal("1", AgentUpdaterContract.Version);
        Assert.Equal(1, AgentUpdaterContract.VersionNumber);
        Assert.Equal("--attempt", AgentUpdaterContract.AttemptArgument);
        Assert.Equal("agent.update.plan.v2", AgentUpdaterContract.PlanSchema);
        Assert.Equal("agent.update.journal.v1", AgentUpdaterContract.JournalSchema);
        Assert.Equal("launch_requested", AgentUpdaterContract.LaunchRequestedPhase);
        Assert.Equal("install_may_have_started", AgentUpdaterContract.InstallMayHaveStartedPhase);
        Assert.Equal("CERBERUS_EULA_ACCEPTED", AgentUpdaterContract.EulaAcceptedProperty);
        Assert.Equal("CERBERUS_LAB_TRANSACTION", AgentUpdaterContract.LabTransactionProperty);
        Assert.Equal("CERBERUS_UPDATE_REQUIRE_BACKEND", AgentUpdaterContract.RequireBackendProperty);
        Assert.Equal(new[] { 0, 3010 }, AgentUpdaterContract.SuccessExitCodes);
        Assert.Equal("installer-transactions", AgentUpdaterContract.InstallerTransactionsDirectoryName);
    }

    [Fact]
    public void UpdaterMsiArguments_MatchContract()
    {
        var updater = ReadSource("Cerberus.Agent.Updater", "Program.cs");
        Assert.Contains($"\"{AgentUpdaterContract.EulaAcceptedProperty}=1\"", updater);
        Assert.Contains($"\"{AgentUpdaterContract.LabTransactionProperty}=\"", updater);
        Assert.Contains($"\"{AgentUpdaterContract.RequireBackendProperty}=1\"", updater);
        Assert.Contains("\"/norestart\"", updater);
    }

    [Theory]
    [InlineData("server", true)]
    [InlineData("desktop", false)]
    public void Package_DeclaresUpdaterMsiPropertiesSecurePerProfile(string profile, bool requireBackend)
    {
        var package = XDocument.Parse(ServerPackageStaticTests.Evaluate(profile, "stable"));
        var wix = package.Root!.Name.Namespace;
        var properties = package.Descendants(wix + "Property").ToArray();
        void IsSecure(string id)
        {
            var property = Assert.Single(properties.Where(prop => (string?)prop.Attribute("Id") == id));
            Assert.Equal("yes", (string?)property.Attribute("Secure"));
        }

        IsSecure(AgentUpdaterContract.EulaAcceptedProperty);
        IsSecure(AgentUpdaterContract.LabTransactionProperty);
        if (requireBackend)
            IsSecure(AgentUpdaterContract.RequireBackendProperty);
        else
            Assert.True(!properties.Any(prop => (string?)prop.Attribute("Id") == AgentUpdaterContract.RequireBackendProperty),
                "The desktop package currently does not declare CERBERUS_UPDATE_REQUIRE_BACKEND.");
    }

    [Fact]
    public void UpdaterSources_NeverPassMsiexecUninstall()
    {
        var source = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src");
        foreach (var project in new[] { "Cerberus.Agent.Updater", "Cerberus.Agent.Update.Core" })
        {
            var root = Path.Combine(source, project);
            foreach (var file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(root, file);
                if (relative.Split(Path.DirectorySeparatorChar).Any(part => part is "bin" or "obj"))
                    continue;

                var text = File.ReadAllText(file);
                Assert.False(Regex.IsMatch(text, @"\bMsiConfigureProduct\w*\s*\(", RegexOptions.IgnoreCase),
                    $"Forbidden Windows Installer API in {project}/{relative}.");
                foreach (Match argument in Regex.Matches(text, @"\bArgumentList\.Add\s*\((?<value>[^;]+)\);"))
                {
                    Assert.False(Regex.IsMatch(argument.Groups["value"].Value,
                        @"(?<![\w/])(?:/x|/uninstall|REMOVE=ALL)(?![\w])", RegexOptions.IgnoreCase),
                        $"Forbidden Windows Installer argument in {project}/{relative}.");
                }
            }
        }
    }

    private static IEnumerable<string> ConstantsOf(Type type)
        => type.GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!);

    private static string ReadSource(string project, string name)
        => File.ReadAllText(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", project, name));
}
