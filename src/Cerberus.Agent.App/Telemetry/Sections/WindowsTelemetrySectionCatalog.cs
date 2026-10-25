using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal static class WindowsTelemetrySectionCatalog
{
    private const string SectionAllowlistEnv = "CERBERUS_AGENT_TELEMETRY_SECTIONS";

    // Sections sent in the server build profile; the environment allowlist is not consulted there.
    private static readonly HashSet<string> ServerProfileSections = new(StringComparer.OrdinalIgnoreCase)
    {
        "os", "resources", "clock", "runtime", "firewall", "network", "security", "identity",
    };

    public static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateDefault()
        => CreateDefault(Environment.GetEnvironmentVariable(SectionAllowlistEnv), publishServiceObservation: false);

    internal static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateDefault(string? configured)
        => CreateDefault(configured, publishServiceObservation: false);

    internal static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateDefault(bool publishServiceObservation)
        => CreateDefault(Environment.GetEnvironmentVariable(SectionAllowlistEnv), publishServiceObservation);

    internal static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateDefault(
        string? configured,
        bool publishServiceObservation)
    {
        var sections = CreateAll(publishServiceObservation);
        if (AgentBuildProfile.IsServer)
            return sections.Where(section => ServerProfileSections.Contains(section.SectionName)).ToArray();

        if (string.IsNullOrWhiteSpace(configured))
            return sections;

        var allowlist = configured
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (allowlist.Count == 0)
            return sections;

        var filtered = sections
            .Where(section => allowlist.Contains(section.SectionName))
            .ToArray();

        return filtered.Length == 0
            ? sections
            : filtered;
    }

    private static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateAll(bool publishServiceObservation) => new IWindowsTelemetrySectionCollector[]
    {
        new IdentityTelemetrySectionCollector(),
        new OsTelemetrySectionCollector(),
        new ResourcesTelemetrySectionCollector(),
        new NetworkTelemetrySectionCollector(),
        new TailscaleTelemetrySectionCollector(),
        new RdpTelemetrySectionCollector(),
        new FirewallTelemetrySectionCollector(),
        new SecurityTelemetrySectionCollector(),
        new ClockTelemetrySectionCollector(),
        new RuntimeTelemetrySectionCollector(),
        publishServiceObservation
            ? new CapabilitiesTelemetrySectionCollector(
                LocalUserCommandPolicy.Resolve,
                LocalUserCommandPolicy.WriteServiceObservation)
            : new CapabilitiesTelemetrySectionCollector(),
    };
}
