namespace Cerberus.Agent.App.Telemetry;

internal interface IWindowsTelemetrySectionCollector
{
    string SectionName { get; }

    ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct);
}
