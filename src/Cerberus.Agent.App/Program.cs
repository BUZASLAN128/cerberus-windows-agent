using System.Windows;
using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.App.Localization;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.App;

internal static class Program
{
    private const string UiMutexName = "Global\\CerberusAgent.Ui.SingleInstance";
    private const string UiPipeName = "CerberusAgent.Ui.SingleInstancePipe";
    [STAThread]
    public static int Main(string[] args)
    {
        AgentLocalizer.ApplyThreadCulture();
        var parsed = Args.Parse(args ?? Array.Empty<string>());

        if (parsed.AcceptEula)
        {
            var scope = (parsed.InstallService || parsed.Service) && Elevation.IsAdministrator()
                ? LegalConsentScope.Machine
                : LegalConsentScope.User;
            AgentLegalConsent.Accept(scope, "cli");
            Console.WriteLine($"Accepted {AgentLegalConsent.CurrentConsentSummary}.");

            if (IsAcceptEulaOnly(parsed))
                return 0;
        }

        if (parsed.Register)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            return RegisterMode.RunAsync(parsed, cts.Token).GetAwaiter().GetResult();
        }

        if (parsed.Setup)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(7));
            return SetupMode.RunAsync(cts.Token).GetAwaiter().GetResult();
        }

        if (parsed.HeartbeatOnce)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            return HeartbeatOnceMode.RunAsync(cts.Token).GetAwaiter().GetResult();
        }

        if (!string.IsNullOrWhiteSpace(parsed.ApplyUpdatePlan))
            return 2;

        if (parsed.UpdateCheckOnce || parsed.UpdateApplyOnce)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(parsed.UpdateApplyOnce ? 15 : 2));
            return UpdateCommandMode
                .RunAsync(apply: parsed.UpdateApplyOnce, cts.Token)
                .GetAwaiter()
                .GetResult();
        }

        if (parsed.EnableLocalUserCreate || parsed.DisableLocalUserCreate)
        {
            try
            {
                LocalUserCommandPolicy.WriteRegistryCreateEnabled(parsed.EnableLocalUserCreate);
                Console.WriteLine(parsed.EnableLocalUserCreate
                    ? "Local user create policy enabled."
                    : "Local user create policy disabled.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 2;
            }
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

        return RunUi(ParseStartupSignal(parsed));
    }

    private static bool IsAcceptEulaOnly(AgentArgs args)
        => args.AcceptEula &&
           !args.Register &&
           !args.Setup &&
           !args.HeartbeatOnce &&
           !args.ExportTailscaleUp &&
           !args.SelfTest &&
           !args.Background &&
           !args.Open &&
           !args.Connect &&
           !args.CheckUpdates &&
           !args.UpdateNow &&
           !args.UpdateCheckOnce &&
           !args.UpdateApplyOnce &&
           !args.EnableLocalUserCreate &&
           !args.DisableLocalUserCreate &&
           !args.InstallService &&
           !args.UninstallService &&
           !args.UnregisterDevice &&
           !args.StartService &&
           !args.StopService &&
           !args.Service &&
           string.IsNullOrWhiteSpace(args.ApplyUpdatePlan);

    private static string? ParseStartupSignal(AgentArgs args)
    {
        if (args.UpdateNow)
            return AgentUiSignals.UpdateNow;
        if (args.CheckUpdates)
            return AgentUiSignals.CheckUpdates;
        if (args.Connect)
            return AgentUiSignals.Connect;
        if (args.Open)
            return AgentUiSignals.Open;
        return null;
    }

    private static int RunUi(string? startupSignal)
    {
        if (!ProcessInstanceGuard.TryAcquire(UiMutexName, UiPipeName, startupSignal, out var instanceGuard))
            return 0;

        using var guard = instanceGuard!;
        var app = new App
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown,
        };

        using var tray = new TrayHost();
        guard.StartSignalListener(tray.HandleSignal);
        if (!string.IsNullOrWhiteSpace(startupSignal))
            tray.HandleSignal(startupSignal);

        return app.Run();
    }
}
