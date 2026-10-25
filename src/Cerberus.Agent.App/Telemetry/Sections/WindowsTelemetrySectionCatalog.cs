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
        "sessions", "hardware", "services", "listening_ports", "updates", "software",
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

    private static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateAll(bool publishServiceObservation)
    {
        var sections = CreateCoreSections(publishServiceObservation);
#if CERBERUS_SERVER_PROFILE
        // Core sections run under the same run budget, so a slow core collector cannot start outside it.
        return sections
            .Select(section => (IWindowsTelemetrySectionCollector)new ServerSectionBudget(section, TimeProvider.System))
            .Concat(CreateServerFactSections(TimeProvider.System))
            .ToArray();
#else
        return sections;
#endif
    }

#if CERBERUS_SERVER_PROFILE
    internal static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateServerFactSections(TimeProvider time)
    {
        IWindowsTelemetrySectionCollector[] facts =
        {
            new SessionsTelemetrySectionCollector(),
            new HardwareTelemetrySectionCollector(),
            new ServicesTelemetrySectionCollector(),
            new ListeningPortsTelemetrySectionCollector(),
            new UpdatesTelemetrySectionCollector(),
            new SoftwareTelemetrySectionCollector(),
        };
        return facts.Select(section => (IWindowsTelemetrySectionCollector)new ServerSectionBudget(section, time)).ToArray();
    }
#endif

    private static IWindowsTelemetrySectionCollector[] CreateCoreSections(bool publishServiceObservation) => new IWindowsTelemetrySectionCollector[]
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
