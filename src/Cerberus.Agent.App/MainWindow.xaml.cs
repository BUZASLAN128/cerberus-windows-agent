using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.App.Localization;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using MediaColor = System.Windows.Media.Color;

namespace Cerberus.Agent.App;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer;
    private volatile bool _busy;
    private int _refreshing;
    private DateTimeOffset _ignoreDeactivateUntil = DateTimeOffset.MinValue;
    private DateTimeOffset _nextRegistrationReconcileAt = DateTimeOffset.MinValue;
    private RuntimeUiConfig _config;
    private bool _setupComplete;

    internal bool IsBusy => _busy;

    public MainWindow()
    {
        InitializeComponent();
        ApplyLocalizedText();

        _config = UiConfigStore.LoadMergedWithEnv();

        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(5),
        };
        _timer.Tick += async (_, _) => await RefreshAsync();

        Loaded += async (_, _) =>
        {
            await Dispatcher.InvokeAsync(async () =>
            {
                PositionNearNotificationArea();
                await RefreshAsync();
                if (IsVisible)
                    _timer.Start();
            });
        };

        IsVisibleChanged += (_, _) =>
        {
            if (IsVisible)
            {
                PositionNearNotificationArea();
                _timer.Start();
                _ = Dispatcher.InvokeAsync(async () => await RefreshAsync());
                return;
            }

            _timer.Stop();
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

    internal void PositionNearNotificationArea()
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(PositionNearNotificationArea);
            return;
        }

        const int marginPx = 12;
        UpdateLayout();

        var screen = System.Windows.Forms.Screen.FromPoint(System.Windows.Forms.Cursor.Position);
        var workingArea = screen.WorkingArea;
        var widthDip = ActualWidth > 0 ? ActualWidth : Width;
        var heightDip = ActualHeight > 0 ? ActualHeight : Height;
        var source = PresentationSource.FromVisual(this);
        var toDevice = source?.CompositionTarget?.TransformToDevice ?? Matrix.Identity;
        var fromDevice = source?.CompositionTarget?.TransformFromDevice ?? Matrix.Identity;

        var sizePx = toDevice.Transform(new Vector(widthDip, heightDip));
        var leftPx = Math.Max(workingArea.Left, workingArea.Right - sizePx.X - marginPx);
        var topPx = Math.Max(workingArea.Top, workingArea.Bottom - sizePx.Y - marginPx);
        var originDip = fromDevice.Transform(new System.Windows.Point(leftPx, topPx));

        Left = originDip.X;
        Top = originDip.Y;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
            Hide();
        else
            Close();
    }

    // NOTE: We intentionally do NOT auto-hide on Deactivate/MouseLeave.
    // Auto-hide makes the control center feel "buggy" because the first click can deactivate
    // the window (focus stealing rules) and close it unexpectedly.

    private void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Escape)
        {
            if (_busy)
                Hide();
            else
                Close();
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

    private void ApplyLocalizedText()
    {
        Title = AgentLocalizer.Get("AppTitle");
        TitleText.Text = AgentLocalizer.Get("AppTitle");
        SubtitleText.Text = AgentLocalizer.Get("AppSubtitle");
        ServiceLabel.Text = AgentLocalizer.Get("Service");
        TailscaleLabel.Text = AgentLocalizer.Get("Connector");
        RegisteredLabel.Text = AgentLocalizer.Get("Registered");
        DeviceSetupLabel.Text = AgentLocalizer.Get("DeviceSetup");
        DeviceSetupDetail.Text = AgentLocalizer.Get("DeviceSetupDetail");
        AdvancedRepairExpander.Header = AgentLocalizer.Get("AdvancedRepairTools");
        ServiceRepairLabel.Text = AgentLocalizer.Get("Service");
        TailscaleRepairLabel.Text = AgentLocalizer.Get("Tailscale");
        InstallSvcBtn.Content = AgentLocalizer.Get("Install");
        UninstallSvcBtn.Content = AgentLocalizer.Get("RemoveService");
        StartSvcBtn.Content = AgentLocalizer.Get("Start");
        StopSvcBtn.Content = AgentLocalizer.Get("Stop");
        UnregisterDeviceBtn.Content = AgentLocalizer.Get("UnregisterDevice");
        ServiceRemovalNote.Text = AgentLocalizer.Get("ServiceRemovalNote");
        ExportTsBtn.Content = AgentLocalizer.Get("ExportTailscale");
        InstallTsBtn.Content = AgentLocalizer.Get("InstallTailscale");
        TailscaleUnavailableNote.Text = AgentLocalizer.Get("TailscaleUnavailableNote");
        AfterSetupNote.Text = AgentLocalizer.Get("AfterSetupNote");
    }

    private async Task RefreshAsync()
    {
        if (!Dispatcher.CheckAccess())
        {
            await Dispatcher.InvokeAsync(() => _ = RefreshAsync());
            return;
        }

        if (Interlocked.Exchange(ref _refreshing, 1) == 1)
            return;

        try
        {
            _config = UiConfigStore.LoadMergedWithEnv();

            // IMPORTANT: Keep the UI responsive. ServiceController calls can block; run off-thread.
            var svcTask = Task.Run(AgentStatus.GetService);
            var registeredTask = Task.Run(AgentStatus.IsRegistered);
            var tsTask = AgentStatus.GetTailscaleAsync(CancellationToken.None);

            var svc = await svcTask;
            var registered = await registeredTask;
            var ts = await tsTask;
            if (!Dispatcher.CheckAccess())
            {
                Interlocked.Exchange(ref _refreshing, 0);
                await Dispatcher.InvokeAsync(() => _ = RefreshAsync());
                return;
            }

            if (registered && !svc.Installed && DateTimeOffset.UtcNow >= _nextRegistrationReconcileAt)
            {
                _nextRegistrationReconcileAt = DateTimeOffset.UtcNow.AddSeconds(60);
                var cleared = await AgentClaimGate.ClearInactiveLocalRegistrationAsync(
                    new DpapiSecretStore(SecretStoreScope.User),
                    CancellationToken.None);
                if (cleared)
                {
                    registered = false;
                    Log("Stored device registration is inactive in the portal; local registration was cleared.");
                }
            }
            var setupComplete = registered && svc.Installed && string.Equals(svc.Text, "running", StringComparison.OrdinalIgnoreCase);
            _setupComplete = setupComplete;

            ServiceValue.Text = svc.Text;
            TailscaleValue.Text = ts.Text;
            RegisteredValue.Text = registered ? AgentLocalizer.Get("Yes") : AgentLocalizer.Get("No");

            var cfgOk = AgentOnboardingFlow.IsConfigReady(_config);
            ReadinessValue.Text = setupComplete ? AgentLocalizer.Get("ReadyToConnect") : AgentLocalizer.Get("SetupRequired");
            ReadinessDetail.Text = setupComplete
                ? AgentLocalizer.Get("ReadyToConnectDetail")
                : AgentLocalizer.Get("SetupRequiredDetail");
            SetReadinessTone(setupComplete);

            OnboardBtn.Content = setupComplete ? AgentLocalizer.Get("Finish") : AgentLocalizer.Get("StartSetup");
            OnboardBtn.IsEnabled = !_busy && (setupComplete || cfgOk);
            if (setupComplete)
            {
                OnboardHint.Text = AgentLocalizer.Get("ReadyHint");
            }
            else if (registered && !svc.Installed)
            {
                OnboardHint.Text = AgentLocalizer.Get("RegisteredInstallServiceHint");
            }
            else if (registered)
            {
                OnboardHint.Text = AgentLocalizer.Format("RegisteredServiceStatusHint", svc.Text);
            }
            else if (!cfgOk)
            {
                OnboardHint.Text = AgentLocalizer.Get("NotConfiguredDetail");
            }
            else
            {
                OnboardHint.Text = AgentLocalizer.Get("NotSetUpYet");
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
                : (File.Exists(machineCmdPath) ? machineCmdPath : AgentLocalizer.Get("CmdNotExported"));
        }
        finally
        {
            Interlocked.Exchange(ref _refreshing, 0);
        }
    }

    private async void Onboard_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
            return;
        if (_setupComplete || AgentStatus.IsSetupComplete())
        {
            Close();
            return;
        }

        var currentService = AgentStatus.GetService();
        if (AgentStatus.IsRegistered() &&
            currentService.Installed &&
            string.Equals(currentService.Text, "running", StringComparison.OrdinalIgnoreCase))
        {
            Close();
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
                    AgentLocalizer.Get("NotConfiguredDetail"),
                    AgentLocalizer.Get("NotConfigured"),
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                Log(AgentLocalizer.Get("NotConfiguredDetail"));
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
            AgentLocalizer.Get("UnregisterDevice"),
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
