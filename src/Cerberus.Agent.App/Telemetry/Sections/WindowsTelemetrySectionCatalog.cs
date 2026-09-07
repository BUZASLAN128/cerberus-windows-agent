using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal static class WindowsTelemetrySectionCatalog
{
    private const string SectionAllowlistEnv = "CERBERUS_AGENT_TELEMETRY_SECTIONS";

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
