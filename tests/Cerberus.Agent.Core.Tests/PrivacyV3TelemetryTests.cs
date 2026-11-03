using System.Text.Json;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.App.Commands;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

[Collection("FailedLogonCursor")]
public sealed class PrivacyV3TelemetryTests
{
    [Theory]
    [InlineData("v2_machine", false)]
    [InlineData("v3_machine", true)]
    [InlineData("v3_user_only", false)]
    [InlineData("wrong_digest", false)]
    [InlineData("missing_digest", false)]
    public void DesktopDetails_RequireCurrentMachineVersionAndContent(string scenario, bool expected)
    {
        var values = CurrentMachineValues();
        if (scenario == "v2_machine") values["privacyNoticeVersion"] = "agent-privacy-2026-06-02.v2";
        if (scenario == "wrong_digest") values["privacyNoticeSha256"] = new string('0', 64);
        if (scenario == "missing_digest") values.Remove("privacyNoticeSha256");
        var scopes = new List<LegalConsentScope>();
        var allowed = SecurityTelemetryConsent.IsAllowed(false, scope =>
        {
            scopes.Add(scope);
            return scope == LegalConsentScope.Machine
                ? scenario != "v3_user_only" && AgentLegalConsent.IsCurrentMachineMsiConsent(values)
                : scenario == "v3_user_only";
        });
        Assert.Equal(expected, allowed);
        Assert.Equal(new[] { LegalConsentScope.Machine }, scopes);
    }

    [Fact]
    public void ServerPolicy_RemainsIndependentOfNewDesktopConsent()
        => Assert.True(SecurityTelemetryConsent.IsAllowed(true, _ => throw new InvalidOperationException("Server must not query this gate.")));

    [Theory]
    [InlineData("cli", true)]
    [InlineData("install_service", false)]
    [InlineData("tray_control_center", false)]
    public void PromotingUserConsentDoesNotGrantNewMachineCategories(string source, bool expected)
    {
        var record = new AgentLegalConsentRecord("cerberus-agent-legal-consent.v1", AgentLegalConsent.ProductName,
            AgentLegalConsent.EulaVersion, AgentLegalConsent.PrivacyNoticeVersion, AgentLegalConsent.SecurityDisclosureVersion,
            DateTimeOffset.UtcNow, "test", "test", source, AgentLegalConsent.PrivacyNoticeSha256);
        Assert.True(AgentLegalConsent.IsCurrentRecord(record));
        Assert.Equal(expected, AgentLegalConsent.IsCurrentMachinePrivacyRecord(record));
    }

    [Fact]
    public void CompiledProfile_UsesTheApprovedServerDesktopBoundary()
        => Assert.Equal(AgentBuildProfile.IsServer, SecurityTelemetryConsent.IsAllowed(AgentBuildProfile.IsServer, _ => false));

    [Fact]
    public async Task Collector_DeniedConsentReturnsUnavailableDetailsAndKeepsOtherTelemetry()
    {
        var collector = new SecurityTelemetrySectionCollector(false, true, null, hasDetailConsent: () => false);
        var result = JsonSerializer.SerializeToNode(await collector.CollectAsync(ServerFactJson.Context(), default))!.AsObject();
        foreach (var field in new[] { "failed_logons", "successful_logons", "log_cleared", "local_admins" })
            Assert.Equal("unavailable", (string?)result[field]!["status"]);
        foreach (var field in new[] { "defender", "bitlocker", "windows_update", "ad", "unexpected_shutdowns", "defender_av", "smb1" })
            Assert.True(result.ContainsKey(field), field);
        Assert.DoesNotContain("added_by", result.ToJsonString());
    }

    [Fact]
    public async Task DesktopSecondary_PeriodicAndSignedFactsKeepBaselineAndGateNewCategories()
    {
        var sections = WindowsTelemetrySectionCatalog.CreateSignedFacts(
            () => SecurityTelemetryConsent.IsAllowed(AgentBuildProfile.IsServer, _ => false))
            .Where(s => s.SectionName == "security").ToArray();
        var periodic = new WindowsTelemetryCollector(sections, signedFacts: true);
        var snapshot = await periodic.BuildSnapshotAsync(ServerFactJson.Metadata(), null, default);
        AssertSecurityBaseline(JsonSerializer.SerializeToNode(snapshot.Sections["security"])!);
        var handler = new CollectFactsCommandHandler(ServerFactJson.Metadata(), sections, TimeProvider.System);
        using var payload = JsonDocument.Parse("{\"sections\":[\"security\"]}");
        var result = await handler.HandleAsync(new AgentCommand("privacy-facts", "collect_facts", "privacy-facts", payload.RootElement.Clone()), default);
        Assert.Equal("DONE", result.Status);
        AssertSecurityBaseline(JsonSerializer.SerializeToNode(result.PostVerify)!["sections"]!["security"]!);
    }

    private static void AssertSecurityBaseline(System.Text.Json.Nodes.JsonNode security)
    {
        // These are the pre-PR Desktop fields, including in its Secondary signed-facts composition.
        foreach (var field in new[] { "status", "defender", "bitlocker", "windows_update", "ad" })
            Assert.True(security.AsObject().ContainsKey(field), field);
        foreach (var field in new[] { "failed_logons", "successful_logons", "local_admins" })
        {
            Assert.True(security.AsObject().ContainsKey(field), field);
            if (!AgentBuildProfile.IsServer)
                Assert.Equal("unavailable", (string?)security[field]!["status"]);
        }
    }

    [Fact]
    public void LiveSubmission_RechecksConsentAfterBuildAndRehashesWithoutDroppingBaseline()
    {
        var granted = true;
        var policy = new AgentOutboundPrivacyPolicy(() => granted);
        var original = AgentSnapshotFactory.Create(ServerFactJson.Metadata(), DateTimeOffset.UtcNow,
            new Dictionary<string, object?>
            {
                ["security"] = new { status = "ok", ad = new { domain_joined = false },
                    successful_logons = new { user = "PRIVATE_USER" }, local_admins = new { members = new[] { "PRIVATE_MEMBER" } } },
            });
        var json = JsonSerializer.Serialize(original);
        Assert.Same(json, policy.Prepare(json));
        granted = false;
        var prepared = JsonSerializer.Deserialize<AgentSnapshotRequest>(policy.Prepare(json))!;
        if (AgentBuildProfile.IsServer)
        {
            Assert.Equal(json, policy.Prepare(json));
            return;
        }
        var security = JsonSerializer.SerializeToNode(prepared.Sections["security"])!;
        Assert.False(security.AsObject().ContainsKey("local_admins"));
        Assert.False(security.AsObject().ContainsKey("successful_logons"));
        Assert.True(security.AsObject().ContainsKey("ad"));
        Assert.NotEqual(original.SectionHashes["security"], prepared.SectionHashes["security"]);
        Assert.Equal(AgentSnapshotFactory.HashSection(prepared.Sections["security"]), prepared.SectionHashes["security"]);
    }

    [Fact]
    public void ConsentDigest_BindsContentWhileIgnoringOnlyTransportLineEndingsAndBom()
    {
        Assert.Equal(AgentPrivacyDocument.ComputeSha256("a\nb\n"), AgentPrivacyDocument.ComputeSha256("\uFEFFa\r\nb\r\n"));
        Assert.NotEqual(AgentPrivacyDocument.ComputeSha256("a\nb\n"), AgentPrivacyDocument.ComputeSha256("a\nchanged\n"));
        Assert.Equal(64, AgentLegalConsent.PrivacyNoticeSha256.Length);
    }

    [Fact]
    public void JsonConsent_ContainsDigestAndRejectsEditedDocumentIdentity()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-privacy-test-" + Guid.NewGuid().ToString("N"));
        var path = AgentLegalConsent.GetPath(LegalConsentScope.User, root);
        try
        {
            var record = AgentLegalConsent.Accept(LegalConsentScope.User, "unit_test", root);
            Assert.Equal(AgentLegalConsent.PrivacyNoticeSha256, record.PrivacyNoticeSha256);
            Assert.True(AgentLegalConsent.TryLoadCurrent(LegalConsentScope.User, root, out _));
            File.WriteAllText(path, JsonSerializer.Serialize(record with { PrivacyNoticeSha256 = new string('0', 64) }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            Assert.False(AgentLegalConsent.TryLoadCurrent(LegalConsentScope.User, root, out _));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
            if (Directory.Exists(root)) Directory.Delete(root);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ServiceScopeAcceptance_RequiresAdminAndExitsBeforeStartingAWorker(bool administrator)
    {
        var args = Args.Parse(new[] { "--service", "--accept-eula" });
        Assert.Equal(administrator ? LegalConsentScope.Machine : (LegalConsentScope?)null, Program.ResolveAcceptanceScope(args, administrator));
        Assert.True(Program.IsAcceptEulaOnly(args));
        var install = Args.Parse(new[] { "--install-service", "--accept-eula" });
        Assert.False(Program.IsAcceptEulaOnly(install));
        Assert.Equal(administrator ? LegalConsentScope.Machine : (LegalConsentScope?)null, Program.ResolveAcceptanceScope(install, administrator));
        Assert.Equal(LegalConsentScope.User, Program.ResolveAcceptanceScope(Args.Parse(new[] { "--accept-eula" }), administrator));
    }

    private static Dictionary<string, string?> CurrentMachineValues() => new()
    {
        ["accepted"] = "1", ["product"] = AgentLegalConsent.ProductName,
        ["eulaVersion"] = AgentLegalConsent.EulaVersion, ["privacyNoticeVersion"] = AgentLegalConsent.PrivacyNoticeVersion,
        ["privacyNoticeSha256"] = AgentLegalConsent.PrivacyNoticeSha256,
        ["securityDisclosureVersion"] = AgentLegalConsent.SecurityDisclosureVersion,
        ["acceptedVia"] = "msi_explicit", ["acceptanceEvidence"] = "1",
    };
}
