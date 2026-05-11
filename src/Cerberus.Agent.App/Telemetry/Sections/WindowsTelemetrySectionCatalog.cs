namespace Cerberus.Agent.App.Telemetry.Sections;

internal static class WindowsTelemetrySectionCatalog
{
    public static IReadOnlyList<IWindowsTelemetrySectionCollector> CreateDefault() => new IWindowsTelemetrySectionCollector[]
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
        new CapabilitiesTelemetrySectionCollector(),
    };
}
