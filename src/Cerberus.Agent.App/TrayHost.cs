using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.App.Localization;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using System.Drawing;
using System.Net.Http;
using System.ServiceProcess;
using System.Threading;
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
    private readonly TrayIconAnimator _trayIconAnimator;
    private readonly ToolStripMenuItem _workspaceStatus;
    private readonly ToolStripMenuItem _accountStatus;
    private readonly ToolStripMenuItem _serviceStatus;
    private readonly ToolStripMenuItem _tailscaleStatus;
    private readonly ToolStripMenuItem _registeredStatus;
    private readonly ToolStripMenuItem _updateStatus;
    private readonly ToolStripMenuItem _connectDevice;
    private readonly ToolStripMenuItem _checkUpdates;
    private readonly ToolStripMenuItem _updateNow;    private readonly DispatcherTimer _timer;
    private readonly DispatcherTimer _startupUpdateTimer;

    private MainWindow? _window;
    private bool _allowWindowClose;
    private bool _setupComplete;
    private bool _checkingUpdates;
    private bool _applyingUpdate;
    private int _trayActivityCount;
    private int _refreshing;
    private DateTimeOffset _nextRegistrationReconcileAt = DateTimeOffset.MinValue;
    private AgentLocalControlResponse? _lastUpdateStatus;
    private string? _lastPromptedUpdateKey;

    public TrayHost()
    {        _workspaceStatus = new ToolStripMenuItem($"{AgentLocalizer.Get("Workspace")}: -") { Enabled = false };
        _accountStatus = new ToolStripMenuItem($"{AgentLocalizer.Get("Account")}: -") { Enabled = false };
        _serviceStatus = new ToolStripMenuItem(AgentLocalizer.Format("ServiceStatus", "...")) { Enabled = false };
        _tailscaleStatus = new ToolStripMenuItem(AgentLocalizer.Format("ConnectorStatus", "...")) { Enabled = false };
        _registeredStatus = new ToolStripMenuItem(AgentLocalizer.Format("RegisteredStatus", "...")) { Enabled = false };
        _updateStatus = new ToolStripMenuItem(AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateNotChecked"))) { Enabled = false };

        var open = new ToolStripMenuItem(AgentLocalizer.Get("OpenSetup"));
        open.Click += (_, _) => ShowWindow(centerOnScreen: false);

        _connectDevice = new ToolStripMenuItem(AgentLocalizer.Get("ConnectDevice"));
        _connectDevice.Click += (_, _) =>
        {
            RequestHeartbeatBackoffReset("manual_connect");
            ShowWindow(centerOnScreen: true);
        };

        _checkUpdates = new ToolStripMenuItem(AgentLocalizer.Get("CheckUpdates"));
        _checkUpdates.Click += async (_, _) => await CheckUpdatesAsync(userInitiated: true).ConfigureAwait(true);

        _updateNow = new ToolStripMenuItem(AgentLocalizer.Get("UpdateNow")) { Enabled = false };
        _updateNow.Click += async (_, _) => await ApplyCheckedUpdateAsync().ConfigureAwait(true);

        var diagnostics = new ToolStripMenuItem(AgentLocalizer.Get("ExportDiagnostics"));
        diagnostics.Click += async (_, _) => await ExportDiagnosticsAsync();

        var repair = new ToolStripMenuItem(AgentLocalizer.Get("RepairTools"));
        var installService = new ToolStripMenuItem(AgentLocalizer.Get("Install"));
        installService.Click += (_, _) => RunServiceCommand(ServiceControlCommand.Install);
        var removeService = new ToolStripMenuItem(AgentLocalizer.Get("RemoveService"));
        removeService.Click += (_, _) => RunServiceCommand(ServiceControlCommand.Uninstall);
        var startService = new ToolStripMenuItem(AgentLocalizer.Get("Start"));
        startService.Click += (_, _) => RunServiceCommand(ServiceControlCommand.Start);
        var stopService = new ToolStripMenuItem(AgentLocalizer.Get("Stop"));
        stopService.Click += (_, _) => RunServiceCommand(ServiceControlCommand.Stop);
        var unregisterDevice = new ToolStripMenuItem(AgentLocalizer.Get("UnregisterDevice"));
        unregisterDevice.Click += (_, _) => RunServiceCommand(ServiceControlCommand.UnregisterDevice);
        repair.DropDownItems.Add(installService);
        repair.DropDownItems.Add(removeService);
        repair.DropDownItems.Add(startService);
        repair.DropDownItems.Add(stopService);
        repair.DropDownItems.Add(new ToolStripSeparator());
        repair.DropDownItems.Add(unregisterDevice);

        var exit = new ToolStripMenuItem(AgentLocalizer.Get("Quit"));
        exit.Click += (_, _) =>
        {
            Dispose();
            System.Windows.Application.Current.Shutdown();
        };

        var menu = new ContextMenuStrip();
        menu.Items.Add(new ToolStripMenuItem("Cerberus Agent") { Enabled = false });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem(AgentLocalizer.Get("Status")) { Enabled = false });
        menu.Items.Add(_workspaceStatus);
        menu.Items.Add(_accountStatus);
        menu.Items.Add(_serviceStatus);
        menu.Items.Add(_tailscaleStatus);
        menu.Items.Add(_registeredStatus);
        menu.Items.Add(_updateStatus);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(open);
        menu.Items.Add(_connectDevice);
        menu.Items.Add(_checkUpdates);
        menu.Items.Add(_updateNow);
        menu.Items.Add(diagnostics);
        menu.Items.Add(repair);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exit);

        _icon = new NotifyIcon
        {
            Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? "") ?? SystemIcons.Application,
            Text = "Cerberus Agent",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _trayIconAnimator = new TrayIconAnimator(_icon);

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

        _startupUpdateTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(10),
        };
        _startupUpdateTimer.Tick += async (_, _) =>
        {
            _startupUpdateTimer.Stop();
            await CheckUpdatesAsync(userInitiated: false).ConfigureAwait(true);
        };
        _startupUpdateTimer.Start();

        RequestHeartbeatBackoffReset("tray_started");
        _ = RefreshAsync();
    }

    public void HandleSignal(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return;

        System.Windows.Application.Current.Dispatcher.BeginInvoke(() =>
        {
            if (!AgentUiSignals.TryNormalize(message, out var signal))
                return;

            switch (signal)
            {
                case AgentUiSignals.Open:
                    RequestHeartbeatBackoffReset("tray_open_signal");
                    ShowWindow(centerOnScreen: true);
                    break;
                case AgentUiSignals.Connect:
                    RequestHeartbeatBackoffReset("tray_connect_signal");
                    ShowWindow(centerOnScreen: true);
                    break;
                case AgentUiSignals.CheckUpdates:
                    _ = CheckUpdatesAsync(userInitiated: true);
                    break;
                case AgentUiSignals.UpdateNow:
                    _ = ApplyCheckedUpdateAsync();
                    break;
            }
        });
    }

    public async Task RefreshAsync()
    {
        if (Interlocked.Exchange(ref _refreshing, 1) == 1)
            return;

        try
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
            _setupComplete = setupComplete;
            var uiContext = registered ? AgentUiContextStore.ReadBestEffort() : null;

            _workspaceStatus.Text = $"{AgentLocalizer.Get("Workspace")}: {AgentUiContextStore.DisplayTenant(uiContext)}";
            _accountStatus.Text = $"{AgentLocalizer.Get("Account")}: {AgentUiContextStore.DisplayAccount(uiContext)}";
            _serviceStatus.Text = AgentLocalizer.Format("ServiceStatus", svc.Text);
            _tailscaleStatus.Text = AgentLocalizer.Format("ConnectorStatus", ts.Text);
            _registeredStatus.Text = AgentLocalizer.Format("RegisteredStatus", registered ? AgentLocalizer.Get("Yes") : AgentLocalizer.Get("No"));

            _connectDevice.Visible = !setupComplete;
            await RefreshUpdateStateAsync().ConfigureAwait(true);

            _icon.Text = TrimTooltip($"CERBERUS Agent | {svc.Short} | {ts.Short} | reg={(registered ? "yes" : "no")}");
        }
        finally
        {
            Interlocked.Exchange(ref _refreshing, 0);
        }
    }

    public void ShowSetupWindow()
    {
        ShowWindow(centerOnScreen: true);
    }

    private void ShowWindow(bool centerOnScreen)
    {
        RequestHeartbeatBackoffReset(centerOnScreen ? "tray_center_opened" : "tray_flyout_opened");

        // NotifyIcon events are WinForms-threaded; marshal all WPF window ops onto the WPF Dispatcher.
        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            if (_window is null)
            {
                _window = new MainWindow();
                System.Windows.Application.Current.MainWindow = _window;
                _window.Closing += (_, e) =>
                {
                    if (_allowWindowClose)
                        return;

                    e.Cancel = true;
                    _window.Hide();
                };
                _window.Closed += (_, _) =>
                {
                    _window = null;
                };
            }

            if (_window.IsVisible)
            {
                _window.Activate();
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

    private void RunServiceCommand(ServiceControlCommand command)
    {
        if (command == ServiceControlCommand.Install &&
            !LegalConsentPrompt.EnsureUserConsent(null, "service installation"))
        {
            ShowBalloon("Service", "Legal terms were not accepted.", ToolTipIcon.Warning);
            return;
        }

        BeginTrayActivity();
        try
        {
            var result = ServiceControlAction.Run(command);
            ShowBalloon("Service", result.Message, result.Succeeded ? ToolTipIcon.Info : ToolTipIcon.Error);
            _ = RefreshAsync();
        }
        finally
        {
            EndTrayActivity();
        }
    }

    private async Task CheckUpdatesAsync(bool userInitiated)
    {
        if (!userInitiated)
        {
            await RefreshUpdateStateAsync().ConfigureAwait(true);
            return;
        }
        if (_checkingUpdates || _applyingUpdate) return;
        _checkingUpdates = true;
        BeginTrayActivity();
        _checkUpdates.Enabled = false;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var response = await AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("check"), timeout.Token).ConfigureAwait(true);
            ApplyUpdateStateToMenu(response);
            if (!response.Success) ShowUpdateWarning(AgentLocalizer.Get("UpdateCheckFailedDetail"));
        }
        catch (Exception)
        {
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateServiceUnavailable"));
            ShowUpdateWarning(AgentLocalizer.Get("UpdateServiceUnavailable"));
        }
        finally
        {
            _checkingUpdates = false;
            _checkUpdates.Enabled = true;
            EndTrayActivity();
        }
    }

    private async Task ApplyCheckedUpdateAsync(bool consentCaptured = false)
    {
        var displayed = _lastUpdateStatus;
        if (displayed?.AttemptId is null || !AgentUpdateStates.CanApply(displayed.UpdateState))
        {
            ShowUpdateWarning(AgentLocalizer.Get("UpdateCheckRequired"));
            return;
        }
        if (_applyingUpdate || (!consentCaptured && !ConfirmApplyCheckedUpdate())) return;
        _applyingUpdate = true;
        BeginTrayActivity();
        _checkUpdates.Enabled = false;
        _updateNow.Enabled = false;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var response = await AgentLocalControlClient.SendAsync(
                new AgentLocalControlRequest("apply", displayed.AttemptId), timeout.Token).ConfigureAwait(true);
            ApplyUpdateStateToMenu(response);
            if (response.Success)
                ShowBalloon("Cerberus Agent", AgentLocalizer.Get("UpdateServiceRequestedDetail"), ToolTipIcon.Info);
            else
                ShowUpdateWarning(AgentLocalizer.Get("UpdateInstallFailed"));
        }
        catch (Exception)
        {
            ShowUpdateWarning(AgentLocalizer.Get("UpdateServiceUnavailable"));
        }
        finally
        {
            _applyingUpdate = false;
            _checkUpdates.Enabled = true;
            EndTrayActivity();
        }
    }

    private async Task RefreshUpdateStateAsync()
    {
        if (_checkingUpdates || _applyingUpdate) return;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var response = await AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("status"), timeout.Token).ConfigureAwait(true);
            ApplyUpdateStateToMenu(response);
            if (response.Success && response.UpdateState == AgentUpdateStates.AwaitingConsent &&
                response.AttemptId is not null && _lastPromptedUpdateKey != response.AttemptId)
            {
                _lastPromptedUpdateKey = response.AttemptId;
                if (ConfirmApplyCheckedUpdate())
                    await ApplyCheckedUpdateAsync(consentCaptured: true).ConfigureAwait(true);
            }
        }
        catch (Exception)
        {
            _lastUpdateStatus = null;
            _updateNow.Enabled = false;
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateServiceUnavailable"));
        }
    }

    private void ApplyUpdateStateToMenu(AgentLocalControlResponse state)
    {
        _lastUpdateStatus = state;
        _updateNow.Enabled = state.Success && state.AttemptId is not null && AgentUpdateStates.CanApply(state.UpdateState);
        _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", StateLabel(state));
    }

    private static string StateLabel(AgentLocalControlResponse state)
        => state.UpdateState switch
        {
            AgentUpdateStates.Checking => AgentLocalizer.Get("UpdateChecking"),
            AgentUpdateStates.Current or AgentUpdateStates.Installed => AgentLocalizer.Get("UpdateCurrent"),
            AgentUpdateStates.Available => AgentLocalizer.Format("UpdateAvailable", state.TargetVersion ?? "-"),
            AgentUpdateStates.Downloading => AgentLocalizer.Get("UpdateDownloading"),
            AgentUpdateStates.Staged or AgentUpdateStates.AwaitingConsent or AgentUpdateStates.Prompting => AgentLocalizer.Get("UpdateReadyToInstall"),
            AgentUpdateStates.Applying or AgentUpdateStates.InstallerStarted or AgentUpdateStates.Installing => AgentLocalizer.Get("UpdateInstalling"),
            AgentUpdateStates.HealthPending => AgentLocalizer.Get("UpdateHealthPending"),
            AgentUpdateStates.PendingReboot => AgentLocalizer.Get("UpdatePendingReboot"),
            AgentUpdateStates.RetryableBusy => AgentLocalizer.Get("UpdateInstallerBusy"),
            AgentUpdateStates.RecoveryRequired or AgentUpdateStates.Quarantined => AgentLocalizer.Get("UpdateRecoveryRequired"),
            AgentUpdateStates.Blocked => AgentLocalizer.Get("UpdateBlocked"),
            AgentUpdateStates.Failed => AgentLocalizer.Get("UpdateCheckFailed"),
            _ => AgentLocalizer.Get("UpdateNotChecked"),
        };

    private async Task ExportDiagnosticsAsync()
    {
        BeginTrayActivity();
        try
        {
            var path = await AgentDiagnosticsBundle.ExportAsync().ConfigureAwait(true);
            ShowUpdateInfo(AgentLocalizer.Format("DiagnosticsWritten", path));
        }
        catch (Exception ex)
        {
            ShowUpdateWarning(AgentLocalizer.Format("DiagnosticsFailed", AgentDiagnosticsBundle.Redact(ex.Message)));
        }
        finally
        {
            EndTrayActivity();
        }
    }

    private void BeginTrayActivity()
    {
        if (Interlocked.Increment(ref _trayActivityCount) == 1)
            _trayIconAnimator.Start();
    }

    private void EndTrayActivity()
    {
        if (Interlocked.Decrement(ref _trayActivityCount) > 0)
            return;

        Interlocked.Exchange(ref _trayActivityCount, 0);
        _trayIconAnimator.Stop();
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

    private static void RequestHeartbeatBackoffReset(string reason)
        => _ = HeartbeatBackoffResetSignal.TryRequest(reason);

    private bool ConfirmApplyCheckedUpdate()
    {
        if (_lastUpdateStatus?.AttemptId is null || !AgentUpdateStates.CanApply(_lastUpdateStatus.UpdateState))
            return false;

        var version = string.IsNullOrWhiteSpace(_lastUpdateStatus.TargetVersion)
            ? "-"
            : _lastUpdateStatus.TargetVersion;
        var result = System.Windows.Forms.MessageBox.Show(
            AgentLocalizer.Format("UpdateFoundPrompt", version),
            AgentLocalizer.Get("UpdateFoundTitle"),
            System.Windows.Forms.MessageBoxButtons.YesNo,
            System.Windows.Forms.MessageBoxIcon.Information,
            System.Windows.Forms.MessageBoxDefaultButton.Button2);
        return result == System.Windows.Forms.DialogResult.Yes;
    }

    private static void ShowUpdateInfo(string message)
        => ShowUpdateMessage(message, System.Windows.Forms.MessageBoxIcon.Information);

    private static void ShowUpdateWarning(string message)
        => ShowUpdateMessage(message, System.Windows.Forms.MessageBoxIcon.Warning);

    private static void ShowUpdateMessage(string message, System.Windows.Forms.MessageBoxIcon icon)
    {
        System.Windows.Forms.MessageBox.Show(
            message,
            "Cerberus Agent",
            System.Windows.Forms.MessageBoxButtons.OK,
            icon);
    }

    public void Dispose()
    {
        RequestHeartbeatBackoffReset("tray_stopped");
        try { _timer.Stop(); } catch { }
        try { _startupUpdateTimer.Stop(); } catch { }
        try
        {
            if (_window is not null)
            {
                _allowWindowClose = true;
                _window.Close();
            }
        }
        catch { }
        try { _icon.Visible = false; } catch { }
        try { _trayIconAnimator.Dispose(); } catch { }
        try { _icon.Dispose(); } catch { }
    }
}
