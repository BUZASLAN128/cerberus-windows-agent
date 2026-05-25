using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using System.Drawing;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using NotifyIcon = System.Windows.Forms.NotifyIcon;
using ContextMenuStrip = System.Windows.Forms.ContextMenuStrip;
using ToolStripMenuItem = System.Windows.Forms.ToolStripMenuItem;
using ToolStripSeparator = System.Windows.Forms.ToolStripSeparator;
using MouseButtons = System.Windows.Forms.MouseButtons;
using ToolTipIcon = System.Windows.Forms.ToolTipIcon;

namespace Cerberus.Agent.App;

internal sealed class TrayHost : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _statusHeader;
    private readonly ToolStripMenuItem _serviceStatus;
    private readonly ToolStripMenuItem _tailscaleStatus;
    private readonly ToolStripMenuItem _registeredStatus;
    private readonly ToolStripMenuItem _onboard;
    private readonly ToolStripMenuItem _installService;
    private readonly ToolStripMenuItem _uninstallService;
    private readonly ToolStripMenuItem _startService;
    private readonly ToolStripMenuItem _stopService;
    private readonly DispatcherTimer _timer;

    private MainWindow? _window;
    private volatile bool _onboarding;
    private DateTimeOffset _nextRegistrationReconcileAt = DateTimeOffset.MinValue;

    public TrayHost()
    {
        _statusHeader = new ToolStripMenuItem("CERBERUS Agent") { Enabled = false };
        _serviceStatus = new ToolStripMenuItem("Service: ...") { Enabled = false };
        _tailscaleStatus = new ToolStripMenuItem("Tailscale: ...") { Enabled = false };
        _registeredStatus = new ToolStripMenuItem("Registered: ...") { Enabled = false };

        var open = new ToolStripMenuItem("Open") { };
        open.Click += (_, _) => ShowWindow(centerOnScreen: false);

        _onboard = new ToolStripMenuItem("Set up this device");
        _onboard.Click += async (_, _) => await OnboardAsync();

        var exportTs = new ToolStripMenuItem("Export tailscale up cmd");
        exportTs.Click += async (_, _) =>
        {
            using var log = AgentFileLogger.CreateDefault(alsoConsole: false);
            try
            {
                var cfg = UiConfigStore.LoadMergedWithEnv();
                var export = await VpnCommandExportService.ExportAsync(
                    VpnCommandExportService.TryGetConfiguredBackend(cfg),
                    message => log.Info(message),
                    CancellationToken.None);
                if (export.CommandPath is null)
                {
                    ShowBalloon("VPN", "VPN provisioning is not available. Contact your administrator.", ToolTipIcon.Warning);
                    return;
                }
                ShowBalloon("VPN", $"Wrote: {export.CommandPath}", ToolTipIcon.Info);
            }
            catch (Exception ex)
            {
                log.Error("Export tailscale up failed.", ex);
                ShowBalloon("VPN", Sanitizer.Redact(ex.Message), ToolTipIcon.Error);
            }
        };

        var installTs = new ToolStripMenuItem("Install Tailscale");
        installTs.Click += async (_, _) =>
        {
            using var log = AgentFileLogger.CreateDefault(alsoConsole: false);
            try
            {
                await TailscaleInstaller.EnsureInstalledAsync(
                    log: _ => { },
                    ct: CancellationToken.None);
                ShowBalloon("Tailscale", "Install started (UAC may prompt).", ToolTipIcon.Info);
            }
            catch (Exception ex)
            {
                log.Error("Install Tailscale failed.", ex);
                ShowBalloon("Tailscale", Sanitizer.Redact(ex.Message), ToolTipIcon.Error);
            }
        };

        _startService = new ToolStripMenuItem("Start service");
        _startService.Click += (_, _) => RunServiceCommand(ServiceControlCommand.Start);

        _stopService = new ToolStripMenuItem("Stop service");
        _stopService.Click += (_, _) => RunServiceCommand(ServiceControlCommand.Stop);

        _installService = new ToolStripMenuItem("Install service");
        _installService.Click += (_, _) => RunServiceCommand(ServiceControlCommand.Install);

        _uninstallService = new ToolStripMenuItem("Remove service");
        _uninstallService.Click += (_, _) => RunServiceCommand(ServiceControlCommand.Uninstall);

        var unregisterDevice = new ToolStripMenuItem("Unregister device");
        unregisterDevice.Click += (_, _) => RunServiceCommand(ServiceControlCommand.UnregisterDevice);

        var exit = new ToolStripMenuItem("Exit");
        exit.Click += (_, _) =>
        {
            Dispose();
            System.Windows.Application.Current.Shutdown();
        };

        var menu = new ContextMenuStrip();
        menu.Items.Add(_statusHeader);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_serviceStatus);
        menu.Items.Add(_tailscaleStatus);
        menu.Items.Add(_registeredStatus);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(open);
        menu.Items.Add(_onboard);
        menu.Items.Add(exportTs);
        menu.Items.Add(installTs);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_startService);
        menu.Items.Add(_stopService);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_installService);
        menu.Items.Add(_uninstallService);
        menu.Items.Add(unregisterDevice);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exit);

        _icon = new NotifyIcon
        {
            Icon = SystemIcons.Application,
            Text = "CERBERUS Agent",
            Visible = true,
            ContextMenuStrip = menu,
        };

        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
                ShowWindow(centerOnScreen: false);
        };

        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(5),
        };
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
    }

    public async Task RefreshAsync()
    {
        // IMPORTANT: Keep the tray/UI responsive. ServiceController calls can block; run off-thread.
        var svcTask = Task.Run(AgentStatus.GetService);
        var registeredTask = Task.Run(AgentStatus.IsRegistered);
        var tsTask = AgentStatus.GetTailscaleAsync(CancellationToken.None);

        var svc = await svcTask;
        var registered = await registeredTask;
        var ts = await tsTask;
        if (registered && !svc.Installed && DateTimeOffset.UtcNow >= _nextRegistrationReconcileAt)
        {
            _nextRegistrationReconcileAt = DateTimeOffset.UtcNow.AddSeconds(60);
            registered = !await AgentClaimGate.ClearInactiveLocalRegistrationAsync(
                new DpapiSecretStore(SecretStoreScope.User),
                CancellationToken.None);
        }
        var setupComplete = registered && svc.Installed && string.Equals(svc.Text, "running", StringComparison.OrdinalIgnoreCase);

        _serviceStatus.Text = $"Service: {svc.Text}";
        _tailscaleStatus.Text = $"Tailscale: {ts.Text}";
        _registeredStatus.Text = $"Registered: {(registered ? "yes" : "no")}";

        var cfg = UiConfigStore.LoadMergedWithEnv();
        var cfgOk = AgentOnboardingFlow.IsConfigReady(cfg);
        _onboard.Enabled = !_onboarding && !setupComplete && cfgOk;
        _startService.Enabled = svc.CanStart;
        _stopService.Enabled = svc.CanStop;
        _installService.Enabled = !svc.Installed;
        _uninstallService.Enabled = svc.Installed;

        _icon.Text = TrimTooltip($"CERBERUS Agent | {svc.Short} | {ts.Short} | reg={(registered ? "yes" : "no")}");
    }

    public void ShowSetupWindow()
    {
        ShowWindow(centerOnScreen: true);
    }

    private void ShowWindow(bool centerOnScreen)
    {
        // NotifyIcon events are WinForms-threaded; marshal all WPF window ops onto the WPF Dispatcher.
        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            if (_window is null)
            {
                _window = new MainWindow();
                _window.Closing += (_, e) =>
                {
                    // Hide instead of closing to keep tray alive.
                    e.Cancel = true;
                    _window.Hide();
                };
            }

            if (_window.IsVisible)
            {
                if (!centerOnScreen)
                {
                    _window.Hide();
                    return;
                }
            }

            // Prevent immediate auto-hide caused by transient focus changes during Show/Position/Activate.
            _window.SetIgnoreDeactivateFor(TimeSpan.FromMilliseconds(900));
            _window.ShowInTaskbar = centerOnScreen;

            _window.Show();
            if (centerOnScreen)
                CenterWindow(_window);
            else
                PositionFlyout(_window);

            _window.WindowState = WindowState.Normal;
            _window.Activate();
            _window.Topmost = true; // bring to front reliably
            _window.Topmost = false;
            _window.Focus();
        });
    }

    private static void CenterWindow(Window window)
    {
        window.Dispatcher.Invoke(() =>
        {
            window.UpdateLayout();
            var screen = System.Windows.Forms.Screen.FromPoint(System.Windows.Forms.Cursor.Position);
            var wa = screen.WorkingArea;
            var width = window.ActualWidth > 0 ? window.ActualWidth : window.Width;
            var height = window.ActualHeight > 0 ? window.ActualHeight : window.Height;
            window.Left = wa.Left + Math.Max(0, (wa.Width - width) / 2);
            window.Top = wa.Top + Math.Max(0, (wa.Height - height) / 2);
        });
    }

    private static void PositionFlyout(Window window)
    {
        // Anchor the popup to the bottom-right of the current screen work area
        // (similar to Tailscale's tray flyout).
        const int marginPx = 12;

        var cursor = System.Windows.Forms.Cursor.Position;
        var screen = System.Windows.Forms.Screen.FromPoint(cursor);
        var wa = screen.WorkingArea; // device pixels

        // Ensure layout is computed before we read ActualWidth/ActualHeight.
        window.Dispatcher.Invoke(() =>
        {
            window.UpdateLayout();

            var widthDip = window.ActualWidth > 0 ? window.ActualWidth : window.Width;
            var heightDip = window.ActualHeight > 0 ? window.ActualHeight : window.Height;

            var src = PresentationSource.FromVisual(window);
            var toDev = src?.CompositionTarget?.TransformToDevice ?? Matrix.Identity;
            var fromDev = src?.CompositionTarget?.TransformFromDevice ?? Matrix.Identity;

            var sizePx = toDev.Transform(new Vector(widthDip, heightDip));
            var leftPx = wa.Right - sizePx.X - marginPx;
            var topPx = wa.Bottom - sizePx.Y - marginPx;

            var originDip = fromDev.Transform(new System.Windows.Point(leftPx, topPx));
            window.Left = originDip.X;
            window.Top = originDip.Y;
        });
    }

    private async Task OnboardAsync()
    {
        if (_onboarding)
            return;
        var currentService = AgentStatus.GetService();
        if (AgentStatus.IsRegistered() &&
            currentService.Installed &&
            string.Equals(currentService.Text, "running", StringComparison.OrdinalIgnoreCase))
        {
            ShowBalloon("Setup", "Already ready. Device is registered and service is running.", ToolTipIcon.Info);
            return;
        }

        _onboarding = true;
        try
        {
            await RefreshAsync();

            using var log = AgentFileLogger.CreateDefault(alsoConsole: false);

            var cfg = UiConfigStore.LoadMergedWithEnv();
            if (!AgentOnboardingFlow.IsConfigReady(cfg))
            {
                ShowBalloon("Setup", "Not configured. Contact your administrator.", ToolTipIcon.Error);
                return;
            }

            if (!LegalConsentPrompt.EnsureUserConsent(null, "sign-in and device registration"))
            {
                ShowBalloon("Setup", "Legal terms were not accepted.", ToolTipIcon.Warning);
                return;
            }

            ShowBalloon("Setup", "Starting setup. Browser and UAC may open.", ToolTipIcon.Info);
            var result = await new AgentSetupFlow().RunAsync(
                cfg,
                log,
                progress: message => log.Info(message),
                ct: CancellationToken.None);

            ShowBalloon("Setup", result.Message, ToolTipIcon.Info);
        }
        catch (Exception ex)
        {
            ShowBalloon("Setup", Sanitizer.Redact(ex.Message), ToolTipIcon.Error);
        }
        finally
        {
            _onboarding = false;
            await RefreshAsync();
        }
    }

    private void RunServiceCommand(ServiceControlCommand command)
    {
        if (command == ServiceControlCommand.Install &&
            !LegalConsentPrompt.EnsureUserConsent(null, "service installation"))
        {
            ShowBalloon("Service", "Legal terms were not accepted.", ToolTipIcon.Warning);
            return;
        }

        var result = ServiceControlAction.Run(command);
        ShowBalloon("Service", result.Message, result.Succeeded ? ToolTipIcon.Info : ToolTipIcon.Error);
    }

    private void ShowBalloon(string title, string msg, ToolTipIcon icon)
    {
        _icon.BalloonTipTitle = title;
        _icon.BalloonTipText = msg;
        _icon.BalloonTipIcon = icon;
        _icon.ShowBalloonTip(3000);
    }

    private static string TrimTooltip(string s)
    {
        // NotifyIcon.Text is limited (historically 63 chars).
        const int max = 63;
        if (string.IsNullOrEmpty(s))
            return "CERBERUS Agent";
        return s.Length <= max ? s : s[..max];
    }

    public void Dispose()
    {
        try { _timer.Stop(); } catch { }
        try { _icon.Visible = false; } catch { }
        try { _icon.Dispose(); } catch { }
    }
}
