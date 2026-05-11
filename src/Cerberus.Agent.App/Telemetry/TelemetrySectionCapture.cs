using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Telemetry;

internal static class TelemetrySectionCapture
{
    public static async ValueTask<object> CaptureAsync(
        IWindowsTelemetrySectionCollector section,
        WindowsTelemetryContext context,
        CancellationToken ct)
    {
        try
        {
            return await section.CollectAsync(context, ct).ConfigureAwait(false);
        }
        catch (PlatformNotSupportedException ex)
        {
            return Unavailable(section.SectionName, ex.Message);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unavailable(section.SectionName, ex.Message);
        }
        catch (Exception ex)
        {
            return Failed(section.SectionName, ex);
        }
    }

    private static object Unavailable(string section, string reason) => new
    {
        status = "unavailable",
        section,
        reason = Sanitizer.Redact(reason),
    };

    private static object Failed(string section, Exception ex) => new
    {
        status = "failed",
        section,
        error = Sanitizer.Redact($"{ex.GetType().Name}: {ex.Message}"),
    };
}
