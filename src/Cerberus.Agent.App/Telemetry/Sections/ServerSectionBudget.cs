using System.Runtime.CompilerServices;

namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>
/// Time budget for the server profile sections: 20 s per collection run shared by all wrapped sections, at most
/// 5 s each. The run is identified by its <see cref="WindowsTelemetryContext"/> instance, so a new context
/// starts a new budget. A section that runs over, or starts after the budget is spent, reports
/// <c>status: unavailable</c>.
/// </summary>
internal sealed class ServerSectionBudget : IWindowsTelemetrySectionCollector
{
    internal static readonly TimeSpan TotalBudget = TimeSpan.FromSeconds(20);
    internal static readonly TimeSpan SectionBudget = TimeSpan.FromSeconds(5);

    private static readonly ConditionalWeakTable<WindowsTelemetryContext, RunClock> Runs = new();

    private readonly IWindowsTelemetrySectionCollector _inner;
    private readonly TimeProvider _time;

    public ServerSectionBudget(IWindowsTelemetrySectionCollector inner, TimeProvider time)
    {
        _inner = inner;
        _time = time;
    }

    public string SectionName => _inner.SectionName;

    public async ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        var clock = Runs.GetValue(context, _ => new RunClock(now));
        var remaining = TotalBudget - (now - clock.Started);
        if (remaining <= TimeSpan.Zero)
            return ServerFactText.Unavailable(SectionName, "time_budget_exhausted");

        var limit = remaining < SectionBudget ? remaining : SectionBudget;
        using var work = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var timer = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var task = Task.Run(async () => await _inner.CollectAsync(context, work.Token).ConfigureAwait(false), CancellationToken.None);
        var timeout = Task.Delay(limit, _time, timer.Token);

        if (await Task.WhenAny(task, timeout).ConfigureAwait(false) == task)
        {
            timer.Cancel();
            return await task.ConfigureAwait(false);
        }

        ct.ThrowIfCancellationRequested();
        work.Cancel();
        _ = task.ContinueWith(static t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        return ServerFactText.Unavailable(SectionName, "section_timeout");
    }

    private sealed class RunClock
    {
        public RunClock(DateTimeOffset started) => Started = started;

        public DateTimeOffset Started { get; }
    }
}
