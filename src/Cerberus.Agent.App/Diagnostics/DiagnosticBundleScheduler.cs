using System.Text.Json;
using System.IO;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Diagnostics;

internal sealed record DiagnosticBundleSchedulerState(
    string SchemaVersion,
    string? LastSuccessfulUploadUtc,
    string? NextDueUtc);

internal sealed class DiagnosticBundleScheduler
{
    private const string SchemaVersion = "cerberus.agent.diagnostic_scheduler.v1";
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly AgentDiagnosticBundleUploader _uploader;
    private readonly IAgentLogger _log;
    private readonly string _statePath;
    private readonly TimeSpan _interval;
    private readonly TimeSpan _maxJitter;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<int, int> _jitterSeconds;

    public DiagnosticBundleScheduler(
        AgentDiagnosticBundleUploader uploader,
        IAgentLogger log,
        string? statePath = null,
        TimeSpan? interval = null,
        TimeSpan? maxJitter = null,
        Func<DateTimeOffset>? clock = null,
        Func<int, int>? jitterSeconds = null)
    {
        _uploader = uploader;
        _log = log;
        _statePath = statePath ?? DefaultStatePath();
        _interval = interval ?? TimeSpan.FromDays(7);
        _maxJitter = maxJitter ?? TimeSpan.FromHours(6);
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _jitterSeconds = jitterSeconds ?? Random.Shared.Next;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var state = await LoadOrCreateStateAsync(ct).ConfigureAwait(false);
                var nextDue = ParseUtc(state.NextDueUtc) ?? _clock().Add(NextJitter());
                var now = _clock();
                if (now >= nextDue)
                {
                    var ack = await _uploader.UploadAsync(
                        new AgentDiagnosticRequestContext(
                            Source: "scheduled",
                            RequestedBy: "system",
                            RequestCommandId: null,
                            Reason: "weekly_agent_summary"),
                        ct).ConfigureAwait(false);
                    if (string.Equals(ack.Status, "accepted", StringComparison.Ordinal) ||
                        string.Equals(ack.Status, "ignored", StringComparison.Ordinal))
                    {
                        state = new DiagnosticBundleSchedulerState(
                            SchemaVersion,
                            now.ToString("O"),
                            now.Add(_interval).Add(NextJitter()).ToString("O"));
                        await SaveAsync(state, ct).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _log.Warn($"Scheduled diagnostic bundle upload failed: {ex.GetType().Name}: {AgentDiagnosticsBundle.Redact(ex.Message)}");
            }

            await Task.Delay(TimeSpan.FromMinutes(15), ct).ConfigureAwait(false);
        }
    }

    internal async Task<DiagnosticBundleSchedulerState> LoadOrCreateStateAsync(CancellationToken ct)
    {
        var state = await LoadAsync(ct).ConfigureAwait(false);
        if (state is not null)
            return state;

        var initial = new DiagnosticBundleSchedulerState(
            SchemaVersion,
            LastSuccessfulUploadUtc: null,
            NextDueUtc: _clock().Add(NextJitter()).ToString("O"));
        await SaveAsync(initial, ct).ConfigureAwait(false);
        return initial;
    }

    private TimeSpan NextJitter()
    {
        var max = Math.Max(0, (int)Math.Ceiling(_maxJitter.TotalSeconds));
        return max == 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(_jitterSeconds(max + 1));
    }

    private async Task<DiagnosticBundleSchedulerState?> LoadAsync(CancellationToken ct)
    {
        try
        {
            if (!File.Exists(_statePath))
                return null;
            var json = await File.ReadAllTextAsync(_statePath, ct).ConfigureAwait(false);
            var state = JsonSerializer.Deserialize<DiagnosticBundleSchedulerState>(json, JsonOpts);
            return string.Equals(state?.SchemaVersion, SchemaVersion, StringComparison.Ordinal)
                ? state
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            _log.Warn($"Diagnostic scheduler state could not be read: {ex.GetType().Name}");
            return null;
        }
    }

    private async Task SaveAsync(DiagnosticBundleSchedulerState state, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(_statePath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);
        var json = JsonSerializer.Serialize(state, JsonOpts);
        await File.WriteAllTextAsync(_statePath, json, ct).ConfigureAwait(false);
    }

    private static DateTimeOffset? ParseUtc(string? value)
        => DateTimeOffset.TryParse(value, out var parsed)
            ? parsed.ToUniversalTime()
            : null;

    private static string DefaultStatePath()
        => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CerberusAgent",
            "state",
            "diagnostic-scheduler.json");
}
