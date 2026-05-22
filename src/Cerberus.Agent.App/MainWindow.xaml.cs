using Cerberus.Agent.App.Actions;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Cerberus.Agent.App;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer;
    private volatile bool _busy;
    private DateTimeOffset _ignoreDeactivateUntil = DateTimeOffset.MinValue;
    private RuntimeUiConfig _config;

    public MainWindow()
    {
        InitializeComponent();

        _config = UiConfigStore.LoadMergedWithEnv();

        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(5),
        };
        _timer.Tick += async (_, _) => await RefreshAsync();

        Loaded += async (_, _) =>
        {
            await RefreshAsync();
            _timer.Start();
        };

        Closed += (_, _) =>
        {
            try { _timer.Stop(); } catch { }
        };
    }

    internal void SetIgnoreDeactivateFor(TimeSpan duration)
    {
        _ignoreDeactivateUntil = DateTimeOffset.UtcNow.Add(duration);
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        Hide();
    }

    // NOTE: We intentionally do NOT auto-hide on Deactivate/MouseLeave.
    // Auto-hide makes the control center feel "buggy" because the first click can deactivate
    // the window (focus stealing rules) and close it unexpectedly.

    private void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Escape)
        {
            Hide();
            e.Handled = true;
        }
    }

    private void Window_PreviewMouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (!IsActive)
        {
            SetIgnoreDeactivateFor(TimeSpan.FromMilliseconds(500));
            Activate();
            Focus();
        }
    }

    private void Log(string msg)
    {
        var ts = DateTimeOffset.Now.ToString("HH:mm:ss");
        StatusText.AppendText($"[{ts}] {msg}\r\n");
        StatusText.ScrollToEnd();
    }

    private async Task RefreshAsync()
    {
        _config = UiConfigStore.LoadMergedWithEnv();

        // IMPORTANT: Keep the UI responsive. ServiceController calls can block; run off-thread.
        var svcTask = Task.Run(AgentStatus.GetService);
        var registeredTask = Task.Run(AgentStatus.IsRegistered);
        var tsTask = AgentStatus.GetTailscaleAsync(CancellationToken.None);

        var svc = await svcTask;
        var registered = await registeredTask;
        var ts = await tsTask;

        ServiceValue.Text = svc.Text;
        TailscaleValue.Text = ts.Text;
        RegisteredValue.Text = registered ? "yes" : "no";

        var cfgOk = AgentOnboardingFlow.IsConfigReady(_config);
        OnboardBtn.IsEnabled = !_busy && !registered && cfgOk;
        if (registered)
        {
            OnboardHint.Text = "Already registered.";
        }
        else if (!cfgOk)
        {
            OnboardHint.Text = "Not configured. Contact your administrator.";
        }
        else
        {
            OnboardHint.Text = "Not registered yet.";
        }

        InstallSvcBtn.IsEnabled = !_busy && !svc.Installed;
        UninstallSvcBtn.IsEnabled = !_busy && svc.Installed;
        UnregisterDeviceBtn.IsEnabled = !_busy && registered;
        StartSvcBtn.IsEnabled = !_busy && svc.CanStart;
        StopSvcBtn.IsEnabled = !_busy && svc.CanStop;
        ExportTsBtn.IsEnabled = !_busy;
        InstallTsBtn.IsEnabled = !_busy;

        var userCmdPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CerberusAgent",
            "tailscale",
            "tailscale-up.cmd");
        var machineCmdPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CerberusAgent",
            "tailscale",
            "tailscale-up.cmd");
        TsCmdPathLabel.Text = File.Exists(userCmdPath)
            ? userCmdPath
            : (File.Exists(machineCmdPath) ? machineCmdPath : "cmd not exported yet");
    }

    private async void Onboard_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
            return;
        if (AgentStatus.IsRegistered())
        {
            Log("Already registered.");
            await RefreshAsync();
            return;
        }

        _busy = true;
        try
        {
            await RefreshAsync();
            Log("Starting SSO sign-in (browser will open)...");

            _config = UiConfigStore.LoadMergedWithEnv();
            if (!AgentOnboardingFlow.IsConfigReady(_config))
            {
                System.Windows.MessageBox.Show(
                    this,
                    "This device is not configured for onboarding.\n\nPlease contact your administrator.",
                    "Not Configured",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                Log("Onboarding blocked: missing configuration.");
                return;
            }

            using var log = AgentFileLogger.CreateDefault(alsoConsole: false);
            var result = await new AgentOnboardingFlow().RunAsync(
                _config,
                log,
                progress: Log,
                ct: CancellationToken.None);

            Log($"Registered. agent_id={result.Identity.AgentId} tenant_id={result.Identity.TenantId}");

            if (result.TailscaleCommandPath is not null)
                Log($"Wrote tailscale up cmd: {result.TailscaleCommandPath}");
            else
                Log("No tailscale cmd exported.");
        }
        catch (Exception ex)
        {
            Log($"Onboard failed: {Sanitizer.Redact(ex.Message)}");
        }
        finally
        {
            _busy = false;
            await RefreshAsync();
        }
    }

    private void InstallSvc_Click(object sender, RoutedEventArgs e)
    {
        RunServiceCommand(ServiceControlCommand.Install);
    }

    private void UninstallSvc_Click(object sender, RoutedEventArgs e)
    {
        RunServiceCommand(ServiceControlCommand.Uninstall);
    }

    private void UnregisterDevice_Click(object sender, RoutedEventArgs e)
    {
        var answer = System.Windows.MessageBox.Show(
            this,
            "This removes local device registration. You will need to sign in and register again before using the agent.",
            "Unregister device",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning);
        if (answer != MessageBoxResult.OK)
            return;

        RunServiceCommand(ServiceControlCommand.UnregisterDevice);
    }

    private void StartSvc_Click(object sender, RoutedEventArgs e)
    {
        RunServiceCommand(ServiceControlCommand.Start);
    }

    private void StopSvc_Click(object sender, RoutedEventArgs e)
    {
        RunServiceCommand(ServiceControlCommand.Stop);
    }

    private async void ExportTs_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var export = await VpnCommandExportService.ExportAsync(
                VpnCommandExportService.TryGetConfiguredBackend(_config),
                Log,
                CancellationToken.None);
            if (export.CommandPath is null)
            {
                TsCmdPathLabel.Text = "VPN provisioning not available.";
                System.Windows.MessageBox.Show(
                    this,
                    "Bu cihaz icin VPN yetkilendirme bilgisi su an alinmadi.\n\n"
                    + "Kurulusunuz icin VPN entegrasyonu henuz etkin olmayabilir veya gecici olarak erisilemiyor olabilir.\n\n"
                    + "Lutfen daha sonra tekrar deneyin veya sistem yoneticinizle iletisime gecin.",
                    "VPN",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                Log("VPN provisioning is not available (preauth missing).");
            }
            else
            {
                TsCmdPathLabel.Text = export.CommandPath;
                Log($"Wrote cmd: {export.CommandPath}");
            }
        }
        catch (Exception ex)
        {
            Log($"Export failed: {Sanitizer.Redact(ex.Message)}");
        }
        finally
        {
            await RefreshAsync();
        }
    }

    private void RunServiceCommand(ServiceControlCommand command)
    {
        var result = ServiceControlAction.Run(command);
        Log(result.Message);
    }

    private async void InstallTs_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
            return;

        _busy = true;
        try
        {
            await RefreshAsync();
            await TailscaleInstaller.EnsureInstalledAsync(log: Log, ct: CancellationToken.None);
        }
        catch (Exception ex)
        {
            Log($"Install failed: {Sanitizer.Redact(ex.Message)}");
        }
        finally
        {
            _busy = false;
            await RefreshAsync();
        }
    }
}
