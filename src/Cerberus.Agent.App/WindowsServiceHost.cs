using System.ServiceProcess;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.App;

internal sealed class WindowsServiceHost : ServiceBase
{
    internal const int ApplyUpdateCommand = 129;

    private CancellationTokenSource? _cts;
    private Task? _runTask;
    private int _applyUpdateRunning;

    public WindowsServiceHost()
    {
        ServiceName = ServiceInstaller.ServiceName;
        CanStop = true;
        CanPauseAndContinue = false;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        _cts = new CancellationTokenSource();
        _runTask = Task.Run(async () =>
        {
            try
            {
                await ServiceMode.RunAsync(_cts.Token);
            }
            catch
            {
                // Let the service crash; SCM will apply recovery options.
                throw;
            }
        });
    }

    protected override void OnStop()
    {
        try
        {
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
