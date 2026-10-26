using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Telemetry;

internal static class TelemetrySectionCapture
{
    /// <summary>Set at service composition; section failures are otherwise invisible in the service log.</summary>
    internal static IAgentLogger? Log { get; set; }

    private static void LogFailure(string section, Exception ex)
        => Log?.Warn(
            $"Telemetry section {section} {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)} at={ExceptionSite.FirstFrame(ex)}");

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
            LogFailure(section.SectionName, ex);
            return Unavailable(section.SectionName, ex.Message);
        }
        catch (UnauthorizedAccessException ex)
        {
            LogFailure(section.SectionName, ex);
            return Unavailable(section.SectionName, ex.Message);
        }
        catch (Exception ex)
        {
            LogFailure(section.SectionName, ex);
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
