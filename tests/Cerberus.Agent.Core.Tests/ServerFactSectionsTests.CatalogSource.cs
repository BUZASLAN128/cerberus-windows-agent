using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class ServerFactSectionsTests
{
    [Fact]
    public void Catalog_PeriodicProfilesPreserveCoreAndFacts_WhileSignedFactsKeepTheirAllowlist()
    {
        var names = WindowsTelemetrySectionCatalog.CreateDefault((string?)null).Select(s => s.SectionName).ToArray();

        var expected = new List<string> { "identity", "os", "resources", "network", "tailscale", "rdp", "firewall", "security", "clock",
            "runtime", "capabilities", "sessions", "hardware", "services", "listening_ports", "updates", "software", "processes" };
        var signedOutput = EnvelopeTypes.ServerFactSections.ToHashSet(StringComparer.Ordinal);
        if (AgentBuildProfile.IsServer)
        {
            expected.Add(AgentSnapshotFactory.LocalAccountsSection);
            signedOutput.Add(AgentSnapshotFactory.LocalAccountsSection);
        }
        Assert.Equal(expected.OrderBy(n => n), names.OrderBy(n => n));
        Assert.True(signedOutput.SetEquals(WindowsTelemetrySectionCatalog.CreateSignedFacts().Select(s => s.SectionName)));
    }
}
