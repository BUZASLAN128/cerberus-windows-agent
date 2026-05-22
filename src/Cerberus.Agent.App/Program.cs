using System.Windows;
using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.App;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var parsed = Args.Parse(args ?? Array.Empty<string>());

        if (parsed.Register)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            return RegisterMode.RunAsync(parsed, cts.Token).GetAwaiter().GetResult();
        }

        if (parsed.HeartbeatOnce)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            return HeartbeatOnceMode.RunAsync(cts.Token).GetAwaiter().GetResult();
        }

        if (!string.IsNullOrWhiteSpace(parsed.ApplyUpdatePlan))
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            return UpdateApplyMode
                .RunAsync(parsed.ApplyUpdatePlan, parsed.ApplyUpdateTarget, cts.Token)
                .GetAwaiter()
                .GetResult();
        }

        if (parsed.ExportTailscaleUp)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(1));
            return ExportTailscaleUpMode.RunAsync(cts.Token).GetAwaiter().GetResult();
        }

        if (parsed.SelfTest)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            return SelfTestMode.RunAsync(
                    json: parsed.SelfTestJson,
                    outFile: parsed.SelfTestOutFile,
                    ct: cts.Token)
                .GetAwaiter()
                .GetResult();
        }

        if (parsed.InstallService)
        {
            try
            {
                AgentServiceProvisioning.InstallOrThrow();
                Console.WriteLine("Service installed and started.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 2;
            }
        }

        if (parsed.UninstallService)
        {
            try
            {
                AgentServiceProvisioning.UninstallOrThrow();
                Console.WriteLine("Service uninstalled. Device registration preserved.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 2;
            }
        }

        if (parsed.UnregisterDevice)
        {
            try
            {
                AgentServiceProvisioning.UnregisterDeviceOrThrow();
                Console.WriteLine("Device registration removed.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 2;
            }
        }

        if (parsed.StartService)
        {
            try
            {
                ServiceInstaller.StartOrThrow();
                return 0;
            }
            catch
            {
                return 2;
            }
        }

        if (parsed.StopService)
        {
            try
            {
                ServiceInstaller.StopOrThrow();
                return 0;
            }
            catch
            {
                return 2;
            }
        }

        if (parsed.Service)
        {
            if (!Environment.UserInteractive)
            {
                WindowsServiceHost.RunAsService();
                return 0;
            }

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, ev) =>
            {
                ev.Cancel = true;
                cts.Cancel();
            };
            ServiceMode.RunAsync(cts.Token).GetAwaiter().GetResult();
            return 0;
        }

        // Tray single-instance guard. If another tray session is running, ask to close it.
        if (!SingleInstanceGuard.EnsureOrExit())
            return 0;

        var app = new App();

        using var tray = new TrayHost();
        SingleInstanceGuard.StartExitListener(() =>
        {
            try { tray.Dispose(); } catch { }
            try { app.Shutdown(); } catch { }
        });

        // Avoid blocking the STA thread before the WPF dispatcher loop starts.
        // Refresh status once the dispatcher is running.
        app.Dispatcher.BeginInvoke(async () =>
        {
            try { await tray.RefreshAsync(); } catch { }
        });
        var rc = app.Run();
        SingleInstanceGuard.StopExitListener();
        return rc;
    }
}
