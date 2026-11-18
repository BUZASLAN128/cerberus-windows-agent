using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentUpdaterContractTests
{
    [Fact]
    public void Journal_UnknownFields_RoundTripAndStayValueEqual()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-contract-" + Guid.NewGuid().ToString("N"));
        try
        {
            AgentUpdateSecurity.EnsureProtectedRoot(root);
            var path = Path.Combine(root, "transaction.json");
            var now = DateTimeOffset.Parse("2026-11-18T10:00:00Z");
            var journal = new AgentUpdateJournal
            {
                InstallRequest = new(now, 0, now.AddMinutes(10),
                    CommandId: "command", CampaignId: "campaign", IdempotencyKey: "idempotency",
                    ExpectedPlan: new("1.2.3", "dev:42", new string('a', 64))),
                InstallerResult = AgentUpdateInstallerResult.FromMsiExitCode(0, null, null),
                ReconciliationSnapshot = new(AgentUpdateStates.Staged, 0, false, false, null, 0, null, null),
            };
            AgentUpdateDurableFile.Write(path, root, journal);
            var oldBytes = File.ReadAllBytes(path);
            var store = new AgentUpdateJournalStore(root);
            var old = store.Read();
            Assert.Null(old.Extra);
            Assert.Null(old.InstallRequest!.Extra);
            Assert.Null(old.InstallerResult!.Extra);
            Assert.Null(old.ReconciliationSnapshot!.Extra);
            AgentUpdateDurableFile.Write(path, root, old);
            Assert.Equal(oldBytes, File.ReadAllBytes(path));

            var fixture = JsonNode.Parse(oldBytes)!.AsObject();
            fixture["futureRoot"] = JsonNode.Parse("""{"values":[1,true,null]}""");
            fixture["installRequest"]!["futureRequest"] = "request";
            fixture["installerResult"]!["futureInstaller"] = 42;
            fixture["reconciliationSnapshot"]!["futureReconciliation"] = false;
            File.WriteAllText(path, fixture.ToJsonString());

            var first = store.Read();
            var second = store.Read();
            Assert.Equal(first, second);
            Assert.Equal(first.InstallRequest, second.InstallRequest);
            Assert.Equal(first.GetHashCode(), second.GetHashCode());
            var expected = first.InstallRequest;
            var changed = store.Change(before => before.InstallRequest == expected ? before with { NextCheckUtc = now } : before);
            Assert.Equal(now, changed.NextCheckUtc);

            using var rewritten = JsonDocument.Parse(File.ReadAllBytes(path));
            var properties = rewritten.RootElement;
            Assert.Equal("""{"values":[1,true,null]}""", properties.GetProperty("futureRoot").GetRawText());
            Assert.Equal("request", properties.GetProperty("installRequest").GetProperty("futureRequest").GetString());
            Assert.Equal(42, properties.GetProperty("installerResult").GetProperty("futureInstaller").GetInt32());
            Assert.False(properties.GetProperty("reconciliationSnapshot").GetProperty("futureReconciliation").GetBoolean());

            fixture["installRequest"]!["expectedPlan"]!["unknownSignedConstraint"] = true;
            File.WriteAllText(path, fixture.ToJsonString());
            var error = Assert.Throws<InvalidOperationException>(() => store.Read());
            Assert.Equal("Update record is corrupt.", error.Message);
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }
}
