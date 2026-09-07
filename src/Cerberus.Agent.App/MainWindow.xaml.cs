using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.App.Localization;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using MediaColor = System.Windows.Media.Color;

namespace Cerberus.Agent.App;

public partial class MainWindow : Window
{
    private static readonly string AgentVersion = WindowsDeviceInfo.GetAgentVersion();
    private readonly DispatcherTimer _timer;
    private volatile bool _busy;
    private int _refreshing;
    private DateTimeOffset _ignoreDeactivateUntil = DateTimeOffset.MinValue;
    private DateTimeOffset _nextRegistrationReconcileAt = DateTimeOffset.MinValue;
    private DateTimeOffset _localPolicyChangedAtUtc = DateTimeOffset.MinValue;
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

        var screen = System.Windows.Forms.Screen.PrimaryScreen
                     ?? System.Windows.Forms.Screen.FromPoint(System.Windows.Forms.Cursor.Position);
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

    private void ApplyLocalizedText()
    {
        Title = AgentLocalizer.Get("AppTitle");
        LocalUserCreateLabel.Text = AgentLocalizer.Get("LocalUserCreate");
        LocalUserCreateHint.Text = AgentLocalizer.Get("LocalUserCreateHint");
        ActivityLogLabel.Text = AgentLocalizer.Get("Activity");
        SystemInfoLabel.Text = AgentLocalizer.Get("SystemInfo");
        ServiceInfoLabel.Text = AgentLocalizer.Get("ServiceStatusLabel");
        ConnectorInfoLabel.Text = AgentLocalizer.Get("ConnectorStatusLabel");
        RegisteredInfoLabel.Text = AgentLocalizer.Get("RegistrationStatusLabel");
        VersionInfoLabel.Text = AgentLocalizer.Get("AgentVersionLabel");
        LastRefreshInfoLabel.Text = AgentLocalizer.Get("LastRefreshLabel");
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
            var localUserPolicyTask = Task.Run(LocalUserCommandPolicy.ReadConfiguredPolicy);
            var localUserObservationTask = Task.Run(LocalUserCommandPolicy.ReadServiceObservation);
            var tsTask = AgentStatus.GetTailscaleAsync(CancellationToken.None);

            var svc = await svcTask;
            var registered = await registeredTask;
            var localUserPolicy = await localUserPolicyTask;
            var localUserObservation = await localUserObservationTask;
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

            var serviceText = FormatServiceStatus(svc.Text);
            var connectorText = FormatConnectorStatus(ts.Text);
            var registeredText = registered ? AgentLocalizer.Get("Yes") : AgentLocalizer.Get("No");

            ServiceInfoValue.Text = serviceText;
            ConnectorInfoValue.Text = connectorText;
            RegisteredInfoValue.Text = registeredText;
            VersionInfoValue.Text = AgentVersion;
            LastRefreshInfoValue.Text = AgentLocalizer.Get("JustNow");
            SetInfoValueTone(ServiceInfoValue, IsHealthyServiceStatus(svc.Text));
            SetInfoValueTone(ConnectorInfoValue, IsHealthyConnectorStatus(ts.Text));
            SetInfoValueTone(RegisteredInfoValue, registered);
            LocalUserCreateValue.Text = AgentLocalizer.Get(localUserPolicy.State switch
            {
                LocalUserCreatePolicyState.Enabled => "LocalUserCreateSavedEnabled",
                LocalUserCreatePolicyState.Disabled => "LocalUserCreateSavedDisabled",
                _ => "LocalUserCreateUnknown",
            });
            var serviceConfirmed = svc.Installed &&
                string.Equals(svc.Text, "running", StringComparison.OrdinalIgnoreCase) &&
                localUserObservation is not null &&
                localUserObservation.ObservedAtUtc >= _localPolicyChangedAtUtc &&
                localUserObservation.ConfirmsConfiguredState(
                    localUserPolicy, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(2));
            LocalUserCreateObservation.Text = AgentLocalizer.Get(serviceConfirmed
                ? "LocalUserCreateServiceConfirmed"
                : "LocalUserCreateServicePending");
            LocalUserCreateValue.Foreground = localUserPolicy.CreateEnabled
                ? new SolidColorBrush(MediaColor.FromRgb(20, 83, 45))
                : new SolidColorBrush(MediaColor.FromRgb(146, 64, 14));
            LocalUserCreateToggleBtn.Content = localUserPolicy.CreateEnabled
                ? AgentLocalizer.Get("Disable")
                : AgentLocalizer.Get("Enable");
            LocalUserCreateToggleBtn.IsEnabled = !_busy;

            var cfgOk = AgentOnboardingFlow.IsConfigReady(_config);
            var statusReport = BuildStatusReport(registered, svc, ts);
            ReadinessValue.Text = AgentLocalizer.Get("StatusReport");
            ReadinessDetail.Text = statusReport.Detail;
            ReadinessHint.Text = statusReport.Hint;
            SetReadinessTone(statusReport.Tone);

            DeviceSetupLabel.Text = setupComplete ? AgentLocalizer.Get("StatusReport") : AgentLocalizer.Get("DeviceSetup");
            DeviceSetupDetail.Text = setupComplete
                ? AgentLocalizer.Get("StatusReportDetail")
                : AgentLocalizer.Get("DeviceSetupDetail");
            DeviceSetupCard.Visibility = setupComplete ? Visibility.Collapsed : Visibility.Visible;
            OnboardBtn.Content = AgentLocalizer.Get("StartSetup");
            OnboardBtn.Visibility = Visibility.Visible;
            OnboardBtn.IsEnabled = !_busy && cfgOk;
            if (setupComplete)
            {
                OnboardHint.Text = AgentLocalizer.Get("StatusReportReadyHint");
            }
            else if (registered && !svc.Installed)
            {
                OnboardHint.Text = AgentLocalizer.Get("RegisteredInstallServiceHint");
            }
            else if (registered)
            {
                OnboardHint.Text = AgentLocalizer.Format("RegisteredServiceStatusHint", serviceText);
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
            Hide();
            return;
        }

        var currentService = AgentStatus.GetService();
        if (AgentStatus.IsRegistered() &&
            currentService.Installed &&
            string.Equals(currentService.Text, "running", StringComparison.OrdinalIgnoreCase))
        {
            Hide();
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

            using var log = AgentFileLogger.CreateUser(alsoConsole: false);
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

    private static StatusReport BuildStatusReport(
        bool registered,
        (string Text, string Short, bool CanStart, bool CanStop, bool Installed) service,
        (string Text, string Short) connector)
    {
        if (!registered)
        {
            return new StatusReport(
                AgentLocalizer.Get("ReportRegistrationMissingDetail"),
                AgentLocalizer.Get("ReportRegistrationMissingHint"),
                "warning");
        }

        if (!service.Installed || string.Equals(NormalizeStatusKey(service.Text), "not installed", StringComparison.Ordinal))
        {
            return new StatusReport(
                AgentLocalizer.Get("ReportServiceMissingDetail"),
                AgentLocalizer.Get("ReportServiceMissingHint"),
                "warning");
        }

        var serviceKey = NormalizeStatusKey(service.Text);
        if (string.Equals(serviceKey, "stopped", StringComparison.Ordinal))
        {
            return new StatusReport(
                AgentLocalizer.Get("ReportServiceStoppedDetail"),
                AgentLocalizer.Get("ReportServiceStoppedHint"),
                "danger");
        }

        if (string.Equals(serviceKey, "starting", StringComparison.Ordinal) ||
            string.Equals(serviceKey, "stopping", StringComparison.Ordinal))
        {
            return new StatusReport(
                AgentLocalizer.Get("ReportServiceChangingDetail"),
                AgentLocalizer.Get("ReportServiceChangingHint"),
                "info");
        }

        var connectorKey = NormalizeStatusKey(connector.Text);
        if (!string.Equals(connectorKey, "connected", StringComparison.Ordinal))
        {
            return new StatusReport(
                string.Equals(connectorKey, "not installed", StringComparison.Ordinal)
                    ? AgentLocalizer.Get("ReportNetworkMissingDetail")
                    : AgentLocalizer.Get("ReportNetworkIssueDetail"),
                AgentLocalizer.Get("ReportNetworkIssueHint"),
                "warning");
        }

        return new StatusReport(
            AgentLocalizer.Get("StatusReportDetail"),
            AgentLocalizer.Get("StatusReportReadyHint"),
            "ok");
    }

    private void SetReadinessTone(string tone)
    {
        if (string.Equals(tone, "ok", StringComparison.OrdinalIgnoreCase))
        {
            ReadinessPanel.Background = new SolidColorBrush(MediaColor.FromRgb(240, 253, 244));
            ReadinessPanel.BorderBrush = new SolidColorBrush(MediaColor.FromRgb(187, 247, 208));
            ReadinessValue.Foreground = new SolidColorBrush(MediaColor.FromRgb(20, 83, 45));
            ReadinessDetail.Foreground = new SolidColorBrush(MediaColor.FromRgb(22, 101, 52));
            ReadinessHint.Foreground = new SolidColorBrush(MediaColor.FromRgb(22, 101, 52));
            return;
        }

        if (string.Equals(tone, "danger", StringComparison.OrdinalIgnoreCase))
        {
            ReadinessPanel.Background = new SolidColorBrush(MediaColor.FromRgb(254, 242, 242));
            ReadinessPanel.BorderBrush = new SolidColorBrush(MediaColor.FromRgb(254, 202, 202));
            ReadinessValue.Foreground = new SolidColorBrush(MediaColor.FromRgb(153, 27, 27));
            ReadinessDetail.Foreground = new SolidColorBrush(MediaColor.FromRgb(127, 29, 29));
            ReadinessHint.Foreground = new SolidColorBrush(MediaColor.FromRgb(127, 29, 29));
            return;
        }

        if (string.Equals(tone, "info", StringComparison.OrdinalIgnoreCase))
        {
            ReadinessPanel.Background = new SolidColorBrush(MediaColor.FromRgb(239, 246, 255));
            ReadinessPanel.BorderBrush = new SolidColorBrush(MediaColor.FromRgb(191, 219, 254));
            ReadinessValue.Foreground = new SolidColorBrush(MediaColor.FromRgb(30, 64, 175));
            ReadinessDetail.Foreground = new SolidColorBrush(MediaColor.FromRgb(30, 64, 175));
            ReadinessHint.Foreground = new SolidColorBrush(MediaColor.FromRgb(30, 64, 175));
            return;
        }

        ReadinessPanel.Background = new SolidColorBrush(MediaColor.FromRgb(255, 251, 235));
        ReadinessPanel.BorderBrush = new SolidColorBrush(MediaColor.FromRgb(253, 230, 138));
        ReadinessValue.Foreground = new SolidColorBrush(MediaColor.FromRgb(120, 53, 15));
        ReadinessDetail.Foreground = new SolidColorBrush(MediaColor.FromRgb(146, 64, 14));
        ReadinessHint.Foreground = new SolidColorBrush(MediaColor.FromRgb(146, 64, 14));
    }

    private static void SetInfoValueTone(TextBlock textBlock, bool healthy)
    {
        textBlock.Foreground = healthy
            ? new SolidColorBrush(MediaColor.FromRgb(15, 118, 110))
            : new SolidColorBrush(MediaColor.FromRgb(146, 64, 14));
    }

    private static string FormatServiceStatus(string status)
        => NormalizeStatusKey(status) switch
        {
            "running" => AgentLocalizer.Get("ServiceRunning"),
            "stopped" => AgentLocalizer.Get("ServiceStopped"),
            "starting" => AgentLocalizer.Get("ServiceStarting"),
            "stopping" => AgentLocalizer.Get("ServiceStopping"),
            "not installed" => AgentLocalizer.Get("ServiceNotInstalled"),
            "unknown" => AgentLocalizer.Get("StatusUnknown"),
            _ => status,
        };

    private static string FormatConnectorStatus(string status)
        => NormalizeStatusKey(status) switch
        {
            "connected" => AgentLocalizer.Get("ConnectorConnected"),
            "not connected" => AgentLocalizer.Get("ConnectorNotConnected"),
            "not installed" => AgentLocalizer.Get("ConnectorNotInstalled"),
            "unknown" => AgentLocalizer.Get("StatusUnknown"),
            _ => status,
        };

    private static string NormalizeStatusKey(string status)
        => string.IsNullOrWhiteSpace(status)
            ? "unknown"
            : status.Trim().ToLowerInvariant();

    private static bool IsHealthyServiceStatus(string status)
        => string.Equals(NormalizeStatusKey(status), "running", StringComparison.Ordinal);

    private static bool IsHealthyConnectorStatus(string status)
        => string.Equals(NormalizeStatusKey(status), "connected", StringComparison.Ordinal);

    private sealed record StatusReport(string Detail, string Hint, string Tone);

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

    private async void LocalUserCreateToggle_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
            return;

        var current = LocalUserCommandPolicy.ReadConfiguredPolicy();
        var enable = !current.CreateEnabled;
        if (enable)
        {
            var answer = System.Windows.MessageBox.Show(
                this,
                AgentLocalizer.Get("LocalUserCreateEnablePrompt"),
                AgentLocalizer.Get("LocalUserCreate"),
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning);
            if (answer != MessageBoxResult.OK)
                return;
        }

        _busy = true;
        try
        {
            var result = RunLocalUserCreatePolicyCommand(enable);
            if (result.Succeeded)
                _localPolicyChangedAtUtc = DateTimeOffset.UtcNow;
            Log(result.Message);
        }
        finally
        {
            _busy = false;
            await RefreshAsync();
        }
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

    private static ServiceControlResult RunLocalUserCreatePolicyCommand(bool enable)
    {
        var argument = enable ? "--enable-local-user-create" : "--disable-local-user-create";
        if (!Elevation.IsAdministrator())
        {
            return Elevation.TryRunElevated(argument)
                ? new ServiceControlResult(
                    Succeeded: true,
                    enable
                        ? AgentLocalizer.Get("LocalUserCreateEnableElevationOpened")
                        : AgentLocalizer.Get("LocalUserCreateDisableElevationOpened"))
                : new ServiceControlResult(
                    Succeeded: false,
                    AgentLocalizer.Get("ElevationRequestFailed"));
        }

        try
        {
            LocalUserCommandPolicy.WriteRegistryCreateEnabled(enable);
            return new ServiceControlResult(
                Succeeded: true,
                enable
                    ? AgentLocalizer.Get("LocalUserCreateEnabledMessage")
                    : AgentLocalizer.Get("LocalUserCreateDisabledMessage"));
        }
        catch (Exception ex)
        {
            return new ServiceControlResult(
                Succeeded: false,
                AgentLocalizer.Format("LocalUserCreatePolicyFailed", Sanitizer.Redact(ex.Message)));
        }
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
