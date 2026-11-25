using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal static class WindowsTelemetrySectionCatalog
{
    // The shared Server catalog includes account inventory for periodic snapshots and wildcard facts results.
    private static readonly HashSet<string> ServerProfileSections =
        new(AgentBuildProfile.IsServer
            ? EnvelopeTypes.ServerFactSections.Append(AgentSnapshotFactory.LocalAccountsSection)
            : EnvelopeTypes.ServerFactSections, StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateDefault()
        => CreateDefault(Environment.GetEnvironmentVariable(AgentSnapshotFactory.SnapshotSectionAllowlistEnv), publishServiceObservation: false);

    internal static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateDefault(string? configured)
        => CreateDefault(configured, publishServiceObservation: false);

    internal static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateDefault(bool publishServiceObservation)
        => CreateDefault(Environment.GetEnvironmentVariable(AgentSnapshotFactory.SnapshotSectionAllowlistEnv), publishServiceObservation);

    internal static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateDefault(
        string? configured,
        bool publishServiceObservation,
        LocalAccountsTelemetrySectionCollector? localAccounts = null)
    {
        var sections = CreateAll(publishServiceObservation, localAccounts);
        var configuredSections = AgentSnapshotFactory.ParseSnapshotSectionAllowlist(configured);
        if (configuredSections.Length == 0)
            return sections;

        var allowlist = configuredSections.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var baseline = sections.Where(section => section.SectionName != AgentSnapshotFactory.LocalAccountsSection).ToArray();
        var filtered = baseline.Where(section => allowlist.Contains(section.SectionName)).ToArray();

        return filtered.Length == 0 ? baseline : filtered;
    }

    private static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateAll(bool publishServiceObservation,
        LocalAccountsTelemetrySectionCollector? localAccounts)
    {
        var sections = CreateCoreSections(publishServiceObservation, null, localAccounts);
        // Core sections run under the same run budget, so a slow core collector cannot start outside it.
        return sections
            .Select(section => (IWindowsTelemetrySectionCollector)new ServerSectionBudget(section, TimeProvider.System))
            .Concat(CreateServerFactSections(TimeProvider.System))
            .ToArray();
    }

    internal static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateSignedFacts(Func<bool>? hasDetailConsent = null,
        LocalAccountsTelemetrySectionCollector? localAccounts = null)
        => CreateCoreSections(false, hasDetailConsent, localAccounts)
            .Select(section => (IWindowsTelemetrySectionCollector)new ServerSectionBudget(section, TimeProvider.System))
            .Concat(CreateServerFactSections(TimeProvider.System))
            .Where(section => ServerProfileSections.Contains(section.SectionName))
            .ToArray();

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
            new ProcessesTelemetrySectionCollector(),
        };
        return facts.Select(section => (IWindowsTelemetrySectionCollector)new ServerSectionBudget(section, time)).ToArray();
    }
    private static IEnumerable<IWindowsTelemetrySectionCollector> CreateCoreSections(bool publishServiceObservation,
        Func<bool>? hasDetailConsent, LocalAccountsTelemetrySectionCollector? localAccounts)
    {
        yield return new IdentityTelemetrySectionCollector();
        yield return new OsTelemetrySectionCollector();
        yield return new ResourcesTelemetrySectionCollector();
        yield return new NetworkTelemetrySectionCollector();
        yield return new TailscaleTelemetrySectionCollector();
        yield return new RdpTelemetrySectionCollector();
        yield return new FirewallTelemetrySectionCollector();
        yield return new SecurityTelemetrySectionCollector(publishServiceObservation, true, null, hasDetailConsent: hasDetailConsent);
        if (AgentBuildProfile.IsServer)
            yield return localAccounts ?? new LocalAccountsTelemetrySectionCollector(hasDetailConsent);
        yield return new ClockTelemetrySectionCollector();
        yield return new RuntimeTelemetrySectionCollector();
        yield return publishServiceObservation
            ? new CapabilitiesTelemetrySectionCollector(
                LocalUserCommandPolicy.Resolve,
                LocalUserCommandPolicy.WriteServiceObservation)
            : new CapabilitiesTelemetrySectionCollector();
    }
}
