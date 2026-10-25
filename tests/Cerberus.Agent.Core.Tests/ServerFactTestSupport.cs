using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>TimeProvider whose clock and timers move only through <see cref="Advance"/>.</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<ManualTimer> _timers = new();
    private DateTimeOffset _now;

    public ManualTimeProvider(DateTimeOffset start) => _now = start;

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate)
            return _now;
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);
        timer.Change(dueTime, period);
        return timer;
    }

    public IReadOnlyList<DateTimeOffset> ActiveDueTimes()
    {
        lock (_gate)
            return _timers.Where(t => t.Due is not null).Select(t => t.Due!.Value).ToArray();
    }

    public void Advance(TimeSpan by)
    {
        lock (_gate)
            _now += by;
        while (true)
        {
            ManualTimer? due;
            lock (_gate)
                due = _timers.Where(t => t.Due is { } d && d <= _now).OrderBy(t => t.Due).FirstOrDefault();
            if (due is null)
                return;
            due.Fire();
        }
    }

    private sealed class ManualTimer : ITimer
    {
        private readonly ManualTimeProvider _owner;
        private readonly TimerCallback _callback;
        private readonly object? _state;
        private TimeSpan _period = Timeout.InfiniteTimeSpan;

        public ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state)
        {
            _owner = owner;
            _callback = callback;
            _state = state;
        }

        public DateTimeOffset? Due { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (_owner._gate)
            {
                _period = period;
                Due = dueTime == Timeout.InfiniteTimeSpan ? null : _owner._now + dueTime;
                if (!_owner._timers.Contains(this))
                    _owner._timers.Add(this);
            }

            return true;
        }

        public void Fire()
        {
            lock (_owner._gate)
                Due = _period == Timeout.InfiniteTimeSpan || _period == TimeSpan.Zero ? null : _owner._now + _period;
            _callback(_state);
        }

        public void Dispose()
        {
            lock (_owner._gate)
            {
                Due = null;
                _owner._timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

internal sealed class FakeUpdateSearcher : IWindowsUpdateSearcher
{
    private readonly Func<CancellationToken, Task<WindowsUpdateScan>> _search;
    private int _calls;

    public FakeUpdateSearcher(Func<CancellationToken, Task<WindowsUpdateScan>> search) => _search = search;

    public int Calls => Volatile.Read(ref _calls);

    public SemaphoreSlim Started { get; } = new(0);

    public Task<WindowsUpdateScan> SearchAsync(CancellationToken ct)
    {
        Interlocked.Increment(ref _calls);
        Started.Release();
        return _search(ct);
    }
}

internal sealed class StubSection : IWindowsTelemetrySectionCollector
{
    private readonly Func<CancellationToken, ValueTask<object>> _run;
    private int _calls;

    public StubSection(string name, Func<CancellationToken, ValueTask<object>> run)
    {
        SectionName = name;
        _run = run;
    }

    public string SectionName { get; }

    public int Calls => Volatile.Read(ref _calls);

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        Interlocked.Increment(ref _calls);
        return _run(ct);
    }
}

internal static class ServerFactJson
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    public static JsonObject Obj(object value) => (JsonObject)JsonSerializer.SerializeToNode(value, Web)!;

    public static IEnumerable<string> PropertyNames(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var pair in obj)
                {
                    yield return pair.Key;
                    foreach (var inner in PropertyNames(pair.Value))
                        yield return inner;
                }

                break;
            case JsonArray array:
                foreach (var item in array)
                foreach (var inner in PropertyNames(item))
                    yield return inner;
                break;
        }
    }

    public static readonly string[] ForbiddenTokens = { "command", "path", "address", "ip", "sid" };

    public static bool HasForbiddenToken(string name)
        => name.ToLowerInvariant().Split('_').Any(token => ForbiddenTokens.Contains(token));

    public static AgentBuildMetadata Metadata() => new("1.2.3", "build-1", "dev", "boot-1", AgentSchemaVersions.All);

    public static WindowsTelemetryContext Context() => new(Metadata(), null);
}
