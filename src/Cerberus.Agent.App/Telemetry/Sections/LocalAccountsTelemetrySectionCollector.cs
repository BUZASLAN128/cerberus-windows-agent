using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class LocalAccountsTelemetrySectionCollector(
    Func<bool>? hasDetailConsent = null,
    Func<WindowsTelemetryContext, CancellationToken, object>? read = null) : IWindowsTelemetrySectionCollector
{
    private static readonly InFlightAccountRead<object> NativeReads = new();
    private readonly InFlightAccountRead<object> _reads = read is null ? NativeReads : new();
    private readonly Func<bool> _hasDetailConsent = hasDetailConsent ?? SecurityTelemetryConsent.IsAllowed;
    private readonly Func<WindowsTelemetryContext, CancellationToken, object> _read = read ?? LocalAccountsProbe.Read;

    public string SectionName => AgentSnapshotFactory.LocalAccountsSection;

    public async ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            if (!_hasDetailConsent())
                return AgentSnapshotFactory.UnavailableLocalAccounts;

            return await _reads.GetOrStart(() => ServerSnapshotFit.FitLocalAccounts(_read(context, CancellationToken.None)))
                .WaitAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            WarnProbe("inventory", ex);
            return AgentSnapshotFactory.UnavailableLocalAccounts;
        }
    }

    internal static void WarnProbe(string probe, Exception ex)
        => TelemetrySectionCapture.Log?.Warn(
            $"Telemetry section local_accounts {probe} {ex.GetType().Name} at={ExceptionSite.FirstFrame(ex)}");
}
