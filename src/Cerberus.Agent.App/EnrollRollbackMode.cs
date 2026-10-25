using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App;

/// <summary><c>--enroll-rollback</c> (server profile): the MSI rollback action for an install-time enroll. Exits 1 only when the data folder is not trusted; nothing is deleted then.</summary>
internal static class EnrollRollbackMode
{
#if CERBERUS_SERVER_PROFILE
    private static readonly TimeSpan LockWait = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan ServiceStopWait = TimeSpan.FromSeconds(30);
#endif

    public static int Run()
    {
#if CERBERUS_SERVER_PROFILE
        var host = new WindowsHeadlessHost();
        if (!AgentUpdateSecurity.IsLocalSystem())
        {
            Console.Error.WriteLine("Enrollment rollback skipped: not running as LocalSystem.");
            return 0;
        }
        // No log and no deletion through a folder that is not trusted; the installer ignores this exit code.
        if (!host.EnsureDataRootProtected())
        {
            Console.Error.WriteLine("Enrollment rollback skipped: the data folder is not trusted.");
            return 1;
        }
        var log = host.OpenLog();
        try
        {
            // A running enroll run owns the staged credentials; wait for it, and never delete them from under it.
            IDisposable? runLock = null;
            try
            {
                runLock = host.TryAcquireEnrollLock(LockWait);
                if (runLock is null)
                    log.Warn("Enrollment rollback skipped: another enroll run still holds the enroll lock.");
            }
            catch (UnauthorizedAccessException)
            {
                log.Warn("Enrollment rollback skipped: the enroll lock is not trusted.");
            }
            using var held = runLock;
            if (held is null)
                return 0;
            StopService(log);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            log.Info(ServerEnrollmentArtifacts.RollbackAsync(cts.Token).GetAwaiter().GetResult());
        }
        catch (Exception ex)
        {
            log.Warn($"Enrollment rollback failed ({ex.GetType().Name}).");
        }
        finally
        {
            (log as IDisposable)?.Dispose();
        }
#endif
        return 0;
    }

#if CERBERUS_SERVER_PROFILE
    // A running service could save refreshed credentials again right after they are deleted.
    private static void StopService(IAgentLogger log)
    {
        try
        {
            if (new WindowsHeadlessHost().GetServiceState() == HeadlessServiceState.NotInstalled)
                return;
            using var service = new System.ServiceProcess.ServiceController(ServiceInstaller.ServiceName);
            if (service.Status == System.ServiceProcess.ServiceControllerStatus.Stopped)
                return;
            if (service.Status != System.ServiceProcess.ServiceControllerStatus.StopPending)
                service.Stop();
            service.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, ServiceStopWait);
        }
        catch (Exception ex)
        {
            log.Warn($"Enrollment rollback continues: the service could not be stopped ({ex.GetType().Name}).");
        }
    }
#endif
}
