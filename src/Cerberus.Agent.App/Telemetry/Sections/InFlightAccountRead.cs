namespace Cerberus.Agent.App.Telemetry.Sections;

/// <summary>Share a native read without retaining its result or giving any one waiter control of its lifetime.</summary>
internal sealed class InFlightAccountRead<TResult>
{
    private readonly object _gate = new();
    private Task<TResult>? _active;

    internal Task<TResult> GetOrStart(Func<TResult> read)
    {
        lock (_gate)
        {
            if (_active is { IsCompleted: false } pending)
                return pending;

            var task = _active = Task.Run(read);
            _ = task.ContinueWith(Clear, CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return task;
        }
    }

    private void Clear(Task<TResult> completed)
    {
        // A native read may finish after every waiter has timed out.
        _ = completed.Exception;
        lock (_gate)
        {
            if (ReferenceEquals(_active, completed))
                _active = null;
        }
    }
}
