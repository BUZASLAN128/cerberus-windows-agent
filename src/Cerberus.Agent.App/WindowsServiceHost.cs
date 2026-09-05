using System.ServiceProcess;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.App;

internal sealed class WindowsServiceHost : ServiceBase
{
    internal const int ApplyUpdateCommand = 129;

    private CancellationTokenSource? _cts;
    private Task? _runTask;
    private int _applyUpdateRunning;
    private int _stopping;

    public WindowsServiceHost()
    {
        ServiceName = ServiceInstaller.ServiceName;
        CanStop = true;
        CanPauseAndContinue = false;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        Interlocked.Exchange(ref _stopping, 0);
        _cts = new CancellationTokenSource();
        _runTask = Task.Run(async () =>
        {
            await ServiceMode.RunAsync(_cts.Token).ConfigureAwait(false);
        });
        _ = _runTask.ContinueWith(
            completed =>
            {
                if (Volatile.Read(ref _stopping) == 1 || !completed.IsFaulted)
                    return;

                // A faulted worker must terminate the process so SCM records a
                // failed service and applies configured recovery. Dormant
                // lifecycle states keep ServiceMode alive and never reach this
                // path.
                var failure = completed.Exception?.GetBaseException();
                Environment.FailFast(
                    $"Cerberus agent worker failed ({failure?.GetType().Name ?? "unknown"}).");
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    protected override void OnStop()
    {
        try
        {
            Interlocked.Exchange(ref _stopping, 1);
            _cts?.Cancel();
            if (_runTask != null && !_runTask.Wait(TimeSpan.FromSeconds(15)))
            {
                // Service stop timeout - task did not complete within 15 seconds.
                // SCM will forcefully terminate the process.
            }
        }
        catch (AggregateException ex)
        {
            // Task was cancelled or faulted during shutdown.
            // Log for diagnostics but allow graceful service stop.
            _ = ex; // Suppress unused variable warning
        }
    }

    protected override void OnCustomCommand(int command)
    {
        if (command == ApplyUpdateCommand)
        {
            StartApplyUpdateCommand();
            return;
        }

        base.OnCustomCommand(command);
    }

    private void StartApplyUpdateCommand()
    {
        if (Interlocked.Exchange(ref _applyUpdateRunning, 1) == 1)
            return;

        _ = Task.Run(async () =>
        {
            try
            {
                await UpdateCommandMode.RunAsync(apply: true, CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Exchange(ref _applyUpdateRunning, 0);
            }
        });
    }

    public static void RunAsService()
    {
        ServiceBase.Run(new WindowsServiceHost());
    }
}
