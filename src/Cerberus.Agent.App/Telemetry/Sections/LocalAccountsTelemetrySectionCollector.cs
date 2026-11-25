using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class LocalAccountsTelemetrySectionCollector(
    Func<bool>? hasDetailConsent = null,
    Func<WindowsTelemetryContext, CancellationToken, object>? read = null) : IWindowsTelemetrySectionCollector
{
    // NetAPI calls cannot be cancelled while inside Windows. A timed-out read keeps this slot until it returns.
    private static int _readInProgress;
    private readonly Func<bool> _hasDetailConsent = hasDetailConsent ?? SecurityTelemetryConsent.IsAllowed;
    private readonly Func<WindowsTelemetryContext, CancellationToken, object> _read = read ?? LocalAccountsProbe.Read;

    public string SectionName => AgentSnapshotFactory.LocalAccountsSection;

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            if (!_hasDetailConsent() || Interlocked.CompareExchange(ref _readInProgress, 1, 0) != 0)
                return ValueTask.FromResult(AgentSnapshotFactory.UnavailableLocalAccounts);

            try
            {
                var section = _read(context, ct);
                ct.ThrowIfCancellationRequested();
                return ValueTask.FromResult(ServerSnapshotFit.FitLocalAccounts(section));
            }
            finally
            {
                Volatile.Write(ref _readInProgress, 0);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            WarnProbe("inventory", ex);
            return ValueTask.FromResult(AgentSnapshotFactory.UnavailableLocalAccounts);
        }
    }

    internal static void WarnProbe(string probe, Exception ex)
        => TelemetrySectionCapture.Log?.Warn(
            $"Telemetry section local_accounts {probe} {ex.GetType().Name} at={ExceptionSite.FirstFrame(ex)}");
}
