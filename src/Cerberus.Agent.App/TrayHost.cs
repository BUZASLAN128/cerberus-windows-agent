using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.App.Localization;
using Cerberus.Agent.App.Updates;
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
    private readonly ToolStripMenuItem _updateNow;
    private readonly AgentUpdateStateStore _updateStateStore;
    private readonly DispatcherTimer _timer;
    private readonly DispatcherTimer _startupUpdateTimer;

    private MainWindow? _window;
    private bool _allowWindowClose;
    private bool _setupComplete;
    private bool _checkingUpdates;
    private bool _applyingUpdate;
    private int _trayActivityCount;
    private int _refreshing;
    private DateTimeOffset _nextRegistrationReconcileAt = DateTimeOffset.MinValue;
    private AgentUpdateSignal? _lastCheckedUpdateSignal;
    private AgentUpdateCheckResult? _lastUpdateCheck;
    private string? _lastPromptedUpdateKey;

    public TrayHost()
    {
        _updateStateStore = AgentUpdateStateStore.CreateDefault();
        _workspaceStatus = new ToolStripMenuItem($"{AgentLocalizer.Get("Workspace")}: -") { Enabled = false };
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
        if (_checkingUpdates || _applyingUpdate)
            return;

        var promptToApplyUpdate = false;
        _checkingUpdates = true;
        BeginTrayActivity();
        _checkUpdates.Enabled = false;
        _updateNow.Enabled = false;
        var currentVersion = WindowsDeviceInfo.GetAgentVersion();
        _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateChecking"));
        await _updateStateStore.TryWriteTransitionAsync(
            AgentUpdateStates.Checking,
            currentVersion,
            CancellationToken.None,
            markChecked: false).ConfigureAwait(true);

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            using var updateHttp = CreateUpdateHttpClient();
            var coordinator = AgentUpdateTrustFactory.BuildCoordinator(updateHttp, NullAgentLogger.Instance, _updateStateStore);
            var signal = AgentUpdateTrustFactory.BuildConfiguredManualSignal();
            if (coordinator is null || signal is null)
            {
                await _updateStateStore.TryWriteTransitionAsync(
                    AgentUpdateStates.Failed,
                    currentVersion,
                    CancellationToken.None,
                    errorCode: AgentUpdateErrorCodes.NotConfigured,
                    errorMessage: "Update trust is not configured.",
                    markChecked: true).ConfigureAwait(true);
                ClearCheckedUpdate(AgentLocalizer.Get("UpdateUnavailable"));
                if (userInitiated)
                    ShowUpdateWarning(AgentLocalizer.Get("UpdateNotConfiguredDetail"));
                return;
            }

            var check = await coordinator.CheckUpdateAsync(signal, cts.Token).ConfigureAwait(true);
            if (!check.Available)
            {
                await _updateStateStore.TryWriteTransitionAsync(
                    AgentUpdateStates.Current,
                    currentVersion,
                    CancellationToken.None,
                    targetVersion: check.Version,
                    channel: signal.Channel,
                    manifestUrl: signal.ManifestUrl,
                    markChecked: true).ConfigureAwait(true);
                ClearCheckedUpdate(AgentLocalizer.Get("UpdateCurrent"));
                if (userInitiated)
                    ShowUpdateInfo(BuildUpdateNotFoundDetail(currentVersion, check.Version));
                return;
            }

            _lastCheckedUpdateSignal = signal;
            _lastUpdateCheck = check;
            await _updateStateStore.TryWriteTransitionAsync(
                AgentUpdateStates.Available,
                currentVersion,
                CancellationToken.None,
                targetVersion: check.Version,
                channel: check.Channel ?? signal.Channel,
                manifestUrl: check.ManifestUrl ?? signal.ManifestUrl,
                markChecked: true).ConfigureAwait(true);
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Format("UpdateAvailable", check.Version ?? "-"));
            _updateNow.Enabled = true;
            promptToApplyUpdate = userInitiated;
        }
        catch (Exception ex)
        {
            var errorCode = AgentUpdateErrorCodes.Classify(ex);
            var errorMessage = AgentDiagnosticsBundle.Redact(ex.Message);
            await _updateStateStore.TryWriteTransitionAsync(
                AgentUpdateStates.Failed,
                currentVersion,
                CancellationToken.None,
                errorCode: errorCode,
                errorMessage: errorMessage,
                markChecked: true).ConfigureAwait(true);
            ClearCheckedUpdate(AgentLocalizer.Get("UpdateCheckFailed"));
            if (userInitiated)
                ShowUpdateWarning(BuildUpdateCheckFailureDetail(errorCode, errorMessage));
        }
        finally
        {
            _checkingUpdates = false;
            _checkUpdates.Enabled = true;
            EndTrayActivity();
        }

        if (promptToApplyUpdate && ConfirmApplyCheckedUpdate())
            await ApplyCheckedUpdateAsync().ConfigureAwait(true);
    }

    private async Task ApplyCheckedUpdateAsync()
    {
        if (_lastCheckedUpdateSignal is null || _lastUpdateCheck is null || !_lastUpdateCheck.Available)
            await RestoreCheckedUpdateFromStateAsync().ConfigureAwait(true);

        if (_lastCheckedUpdateSignal is null || _lastUpdateCheck is null || !_lastUpdateCheck.Available)
        {
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateCheckRequired"));
            _updateNow.Enabled = false;
            return;
        }

        if (_applyingUpdate)
            return;

        _applyingUpdate = true;
        BeginTrayActivity();
        _checkUpdates.Enabled = false;
        _updateNow.Enabled = false;
        _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateInstalling"));

        try
        {
            if (await TryRequestServiceUpdateApplyAsync().ConfigureAwait(true))
                return;

            throw new InvalidOperationException("The Cerberus service is not ready to apply updates.");
        }
        catch (Exception ex)
        {
            await _updateStateStore.TryWriteTransitionAsync(
                AgentUpdateStates.Failed,
                WindowsDeviceInfo.GetAgentVersion(),
                CancellationToken.None,
                targetVersion: _lastUpdateCheck?.Version,
                channel: _lastUpdateCheck?.Channel,
                manifestUrl: _lastUpdateCheck?.ManifestUrl,
                errorCode: AgentUpdateErrorCodes.Classify(ex),
                errorMessage: AgentDiagnosticsBundle.Redact(ex.Message)).ConfigureAwait(true);
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateInstallFailed"));
            ShowUpdateWarning(AgentLocalizer.Format("UpdateInstallFailedDetail", AgentDiagnosticsBundle.Redact(ex.Message)));
            _updateNow.Enabled = _lastUpdateCheck?.Available == true;
        }
        finally
        {
            _applyingUpdate = false;
            _checkUpdates.Enabled = true;
            EndTrayActivity();
        }
    }

    private async Task<bool> TryRequestServiceUpdateApplyAsync()
    {
        var svc = AgentStatus.GetService();
        if (!svc.Installed || !string.Equals(svc.Text, "running", StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            using var controller = new ServiceController(ServiceInstaller.ServiceName);
            controller.ExecuteCommand(WindowsServiceHost.ApplyUpdateCommand);
            await _updateStateStore.TryWriteTransitionAsync(
                AgentUpdateStates.Applying,
                WindowsDeviceInfo.GetAgentVersion(),
                CancellationToken.None,
                targetVersion: _lastUpdateCheck?.Version,
                channel: _lastUpdateCheck?.Channel ?? _lastCheckedUpdateSignal?.Channel,
                manifestUrl: _lastUpdateCheck?.ManifestUrl ?? _lastCheckedUpdateSignal?.ManifestUrl,
                markChecked: true).ConfigureAwait(true);
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateServiceRequested"));
            ShowBalloon("Cerberus Agent", AgentLocalizer.Get("UpdateServiceRequestedDetail"), ToolTipIcon.Info);
            _lastCheckedUpdateSignal = null;
            _lastUpdateCheck = null;
            return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private void ClearCheckedUpdate(string status)
    {
        _lastCheckedUpdateSignal = null;
        _lastUpdateCheck = null;
        _updateNow.Enabled = false;
        _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", status);
    }

    private async Task RefreshUpdateStateAsync()
    {
        if (_checkingUpdates || _applyingUpdate)
            return;

        var state = await _updateStateStore
            .ReconcileInstallerResultAsync(WindowsDeviceInfo.GetAgentVersion(), CancellationToken.None)
            .ConfigureAwait(true);
        ApplyUpdateStateToMenu(state);
        if (string.Equals(state.State, AgentUpdateStates.Prompting, StringComparison.Ordinal))
            await PromptForUpdateOnceAsync(state).ConfigureAwait(true);
    }

    private void ApplyUpdateStateToMenu(AgentUpdateState state)
    {
        _updateNow.Enabled = AgentUpdateStates.CanApply(state.State);
        _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", StateLabel(state));
    }

    private async Task RestoreCheckedUpdateFromStateAsync()
    {
        var state = await _updateStateStore
            .ReconcileInstallerResultAsync(WindowsDeviceInfo.GetAgentVersion(), CancellationToken.None)
            .ConfigureAwait(true);
        if (!AgentUpdateStates.CanApply(state.State) || string.IsNullOrWhiteSpace(state.ManifestUrl))
            return;

        _lastCheckedUpdateSignal = new AgentUpdateSignal(
            Required: false,
            Recommended: true,
            ManifestUrl: state.ManifestUrl,
            Reason: "manual_update_apply",
            Channel: state.Channel ?? WindowsDeviceInfo.GetBuildChannel());
        _lastUpdateCheck = new AgentUpdateCheckResult(
            Available: true,
            Required: false,
            Recommended: true,
            Version: state.TargetVersion,
            Channel: state.Channel,
            Reason: "manual_update_apply",
            ManifestUrl: state.ManifestUrl,
            ArtifactKind: "msi");
        ApplyUpdateStateToMenu(state);
    }

    private async Task PromptForUpdateOnceAsync(AgentUpdateState state)
    {
        var key = $"{state.CampaignId ?? "-"}:{state.TargetVersion ?? "-"}:{state.ArtifactSha256 ?? "-"}";
        if (string.Equals(_lastPromptedUpdateKey, key, StringComparison.Ordinal))
            return;

        _lastPromptedUpdateKey = key;
        await RestoreCheckedUpdateFromStateAsync().ConfigureAwait(true);
        if (_lastUpdateCheck?.Available == true && ConfirmApplyCheckedUpdate())
            await ApplyCheckedUpdateAsync().ConfigureAwait(true);
    }

    private static string StateLabel(AgentUpdateState state)
        => state.State switch
        {
            AgentUpdateStates.NotChecked => AgentLocalizer.Get("UpdateNotChecked"),
            AgentUpdateStates.Checking => AgentLocalizer.Get("UpdateChecking"),
            AgentUpdateStates.Current => AgentLocalizer.Get("UpdateCurrent"),
            AgentUpdateStates.Available => AgentLocalizer.Format("UpdateAvailable", state.TargetVersion ?? "-"),
            AgentUpdateStates.Downloading => AgentLocalizer.Get("UpdateDownloading"),
            AgentUpdateStates.Staged => AgentLocalizer.Get("UpdateReadyToInstall"),
            AgentUpdateStates.Prompting => AgentLocalizer.Get("UpdateReadyToInstall"),
            AgentUpdateStates.Applying => AgentLocalizer.Get("UpdateInstalling"),
            AgentUpdateStates.InstallerStarted => AgentLocalizer.Get("UpdateInstallerStarted"),
            AgentUpdateStates.Applied => AgentLocalizer.Get("UpdateCurrent"),
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

    private static HttpClient CreateUpdateHttpClient()
        => new()
        {
            Timeout = TimeSpan.FromMinutes(10),
        };

    private static string BuildUpdateNotFoundDetail(string currentVersion, string? latestVersion)
        => string.IsNullOrWhiteSpace(latestVersion)
            ? AgentLocalizer.Get("UpdateNotFoundDetail")
            : AgentLocalizer.Format("UpdateNotFoundDetailWithVersions", currentVersion, latestVersion);

    private static string BuildUpdateCheckFailureDetail(string errorCode, string errorMessage)
    {
        var detailKey = errorCode switch
        {
            AgentUpdateErrorCodes.SignatureInvalid => "UpdateCheckFailedSignatureDetail",
            AgentUpdateErrorCodes.ManifestInvalid => "UpdateCheckFailedManifestDetail",
            AgentUpdateErrorCodes.ManifestUnavailable => "UpdateCheckFailedNetworkDetail",
            AgentUpdateErrorCodes.ArtifactUrlDenied => "UpdateCheckFailedArtifactDetail",
            _ => "UpdateCheckFailedDetail",
        };
        var detail = AgentLocalizer.Get(detailKey);
        return string.IsNullOrWhiteSpace(errorMessage)
            ? detail
            : $"{detail}{Environment.NewLine}{Environment.NewLine}{AgentLocalizer.Format("UpdateCheckFailureReason", errorMessage)}";
    }

    private static void RequestHeartbeatBackoffReset(string reason)
        => _ = HeartbeatBackoffResetSignal.TryRequest(reason);

    private bool ConfirmApplyCheckedUpdate()
    {
        if (_lastUpdateCheck is null || !_lastUpdateCheck.Available)
            return false;

        var version = string.IsNullOrWhiteSpace(_lastUpdateCheck.Version)
            ? "-"
            : _lastUpdateCheck.Version;
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
