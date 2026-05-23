using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using MediaColor = System.Windows.Media.Color;

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
        if (!Dispatcher.CheckAccess())
        {
            _ = Dispatcher.BeginInvoke(() => Log(msg), DispatcherPriority.Background);
            return;
        }

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
        var setupComplete = registered && svc.Installed && string.Equals(svc.Text, "running", StringComparison.OrdinalIgnoreCase);

        ServiceValue.Text = svc.Text;
        TailscaleValue.Text = ts.Text;
        RegisteredValue.Text = registered ? "yes" : "no";

        var cfgOk = AgentOnboardingFlow.IsConfigReady(_config);
        ReadinessValue.Text = setupComplete ? "Ready to connect" : "Setup required";
        ReadinessDetail.Text = setupComplete
            ? "This device is registered and the Cerberus Windows service is running."
            : "Run setup to sign in, register this device, and install the Windows service.";
        SetReadinessTone(setupComplete);

        OnboardBtn.Content = setupComplete ? "Ready" : "Start setup";
        OnboardBtn.IsEnabled = !_busy && !setupComplete && cfgOk;
        if (setupComplete)
        {
            OnboardHint.Text = "Ready. Device is registered and service is running.";
        }
        else if (registered && !svc.Installed)
        {
            OnboardHint.Text = "Registered. Finish setup to install the service.";
        }
        else if (registered)
        {
            OnboardHint.Text = $"Registered. Service status: {svc.Text}.";
        }
        else if (!cfgOk)
        {
            OnboardHint.Text = "Not configured. Contact your administrator.";
        }
        else
        {
            OnboardHint.Text = "Not set up yet.";
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
        var currentService = AgentStatus.GetService();
        if (AgentStatus.IsRegistered() &&
            currentService.Installed &&
            string.Equals(currentService.Text, "running", StringComparison.OrdinalIgnoreCase))
        {
            Log("Already ready. Device is registered and service is running.");
            await RefreshAsync();
            return;
        }

        _busy = true;
        try
        {
            await RefreshAsync();
            if (!LegalConsentPrompt.EnsureUserConsent(this, "sign-in and device registration"))
            {
                Log("Onboarding blocked: legal terms were not accepted.");
                return;
            }

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
            var result = await new AgentSetupFlow().RunAsync(
                _config,
                log,
                progress: Log,
                ct: CancellationToken.None);

            Log(result.Message);
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

    private void SetReadinessTone(bool ready)
    {
        if (ready)
        {
            ReadinessPanel.Background = new SolidColorBrush(MediaColor.FromRgb(240, 253, 244));
            ReadinessPanel.BorderBrush = new SolidColorBrush(MediaColor.FromRgb(187, 247, 208));
            ReadinessValue.Foreground = new SolidColorBrush(MediaColor.FromRgb(20, 83, 45));
            ReadinessDetail.Foreground = new SolidColorBrush(MediaColor.FromRgb(22, 101, 52));
            return;
        }

        ReadinessPanel.Background = new SolidColorBrush(MediaColor.FromRgb(255, 251, 235));
        ReadinessPanel.BorderBrush = new SolidColorBrush(MediaColor.FromRgb(253, 230, 138));
        ReadinessValue.Foreground = new SolidColorBrush(MediaColor.FromRgb(120, 53, 15));
        ReadinessDetail.Foreground = new SolidColorBrush(MediaColor.FromRgb(146, 64, 14));
    }

    private void InstallSvc_Click(object sender, RoutedEventArgs e)
    {
        if (!LegalConsentPrompt.EnsureUserConsent(this, "service installation"))
        {
            Log("Service install blocked: legal terms were not accepted.");
            return;
        }

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
