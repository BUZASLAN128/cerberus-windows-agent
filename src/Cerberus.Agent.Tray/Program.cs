using System.Diagnostics;
using System.Drawing;
using System.ServiceProcess;
using System.Windows.Forms;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Localization;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Tray;

internal static class Program
{
    private const string TrayMutexName = "Global\\CerberusAgent.Tray.SingleInstance";
    private const string TrayPipeName = "CerberusAgent.Tray.SingleInstancePipe";
    [STAThread]
    public static void Main(string[] args)
    {
        AgentLocalizer.ApplyThreadCulture();
        var startupSignal = ParseStartupSignal(args);
        if (!ProcessInstanceGuard.TryAcquire(TrayMutexName, TrayPipeName, startupSignal, out var instanceGuard))
            return;

        ApplicationConfiguration.Initialize();
        using (instanceGuard)
        using (var tray = new TrayApplicationContext())
        {
            instanceGuard!.StartSignalListener(tray.HandleSignal);
            if (!string.IsNullOrWhiteSpace(startupSignal))
                tray.HandleSignal(startupSignal);
            Application.Run(tray);
        }
    }

    private static string? ParseStartupSignal(string[]? args)
    {
        if (args is null || args.Length == 0)
            return null;

        bool Has(string value) => args.Any(arg => string.Equals(arg, value, StringComparison.OrdinalIgnoreCase));
        if (Has("--open") || Has("/open"))
            return AgentUiSignals.Open;
        if (Has("--connect") || Has("/connect"))
            return AgentUiSignals.Connect;
        if (Has("--check-updates") || Has("/check-updates"))
            return AgentUiSignals.CheckUpdates;
        if (Has("--update-now") || Has("/update-now"))
            return AgentUiSignals.UpdateNow;
        return null;
    }
}

internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _workspaceStatus;
    private readonly ToolStripMenuItem _accountStatus;
    private readonly ToolStripMenuItem _serviceStatus;
    private readonly ToolStripMenuItem _registeredStatus;
    private readonly ToolStripMenuItem _tailscaleStatus;
    private readonly ToolStripMenuItem _updateStatus;
    private readonly ToolStripMenuItem _connectDevice;
    private readonly ToolStripMenuItem _checkUpdates;
    private readonly ToolStripMenuItem _updateNow;    private readonly System.Windows.Forms.Timer _timer;
    private readonly System.Windows.Forms.Timer _startupUpdateTimer;
    private readonly Control _dispatcher;
    private bool _refreshing;
    private bool _setupComplete;
    private bool _checkingUpdates;
    private bool _applyingUpdate;
    private AgentLocalControlResponse? _lastUpdateStatus;
    private string? _lastPromptedUpdateKey;

    public TrayApplicationContext()
    {        _dispatcher = new Control();
        _dispatcher.CreateControl();

        _workspaceStatus = new ToolStripMenuItem($"{AgentLocalizer.Get("Workspace")}: -") { Enabled = false };
        _accountStatus = new ToolStripMenuItem($"{AgentLocalizer.Get("Account")}: -") { Enabled = false };
        _serviceStatus = new ToolStripMenuItem(AgentLocalizer.Format("ServiceStatus", "...")) { Enabled = false };
        _registeredStatus = new ToolStripMenuItem(AgentLocalizer.Format("RegisteredStatus", "...")) { Enabled = false };
        _tailscaleStatus = new ToolStripMenuItem(AgentLocalizer.Format("ConnectorStatus", "...")) { Enabled = false };
        _updateStatus = new ToolStripMenuItem(AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateNotChecked"))) { Enabled = false };

        _checkUpdates = new ToolStripMenuItem(AgentLocalizer.Get("CheckUpdates"));
        _checkUpdates.Click += async (_, _) => await CheckUpdatesAsync(userInitiated: true).ConfigureAwait(true);

        _updateNow = new ToolStripMenuItem(AgentLocalizer.Get("UpdateNow")) { Enabled = false };
        _updateNow.Click += async (_, _) => await ApplyCheckedUpdateAsync().ConfigureAwait(true);

        _connectDevice = new ToolStripMenuItem(AgentLocalizer.Get("ConnectDevice"));
        _connectDevice.Click += (_, _) =>
        {
            RequestHeartbeatBackoffReset("manual_connect");
            _ = OpenAgentAsync();
        };

        var diagnostics = new ToolStripMenuItem(AgentLocalizer.Get("ExportDiagnostics"));
        diagnostics.Click += async (_, _) => await ExportDiagnosticsAsync();

        var repair = new ToolStripMenuItem(AgentLocalizer.Get("RepairTools"));
        var startService = new ToolStripMenuItem(AgentLocalizer.Get("Start"));
        startService.Click += (_, _) => RunServiceAction(ServiceInstaller.StartOrThrow);

        var stopService = new ToolStripMenuItem(AgentLocalizer.Get("Stop"));
        stopService.Click += (_, _) => RunServiceAction(ServiceInstaller.StopOrThrow);
        repair.DropDownItems.Add(startService);
        repair.DropDownItems.Add(stopService);

        var exit = new ToolStripMenuItem(AgentLocalizer.Get("Quit"));
        exit.Click += (_, _) => ExitThread();

        var menu = new ContextMenuStrip();
        menu.Items.Add(new ToolStripMenuItem("Cerberus Agent") { Enabled = false });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem(AgentLocalizer.Get("Status")) { Enabled = false });
        menu.Items.Add(_workspaceStatus);
        menu.Items.Add(_accountStatus);
        menu.Items.Add(_serviceStatus);
        menu.Items.Add(_registeredStatus);
        menu.Items.Add(_tailscaleStatus);
        menu.Items.Add(_updateStatus);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_connectDevice);
        menu.Items.Add(_checkUpdates);
        menu.Items.Add(_updateNow);
        menu.Items.Add(diagnostics);
        menu.Items.Add(repair);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exit);

        _icon = new NotifyIcon
        {
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application,
            Text = "Cerberus Agent",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
                _ = OpenAgentAsync();
        };

        _timer = new System.Windows.Forms.Timer { Interval = 5000 };
        _timer.Tick += async (_, _) => await RefreshAsync().ConfigureAwait(true);
        _timer.Start();

        _startupUpdateTimer = new System.Windows.Forms.Timer { Interval = 10000 };
        _startupUpdateTimer.Tick += async (_, _) =>
        {
            _startupUpdateTimer.Stop();
            await CheckUpdatesAsync(userInitiated: false).ConfigureAwait(true);
        };
        _startupUpdateTimer.Start();

        RequestHeartbeatBackoffReset("tray_started");
        _ = RefreshAsync();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            RequestHeartbeatBackoffReset("tray_stopped");
            _timer.Stop();
            _timer.Dispose();
            _startupUpdateTimer.Stop();
            _startupUpdateTimer.Dispose();
            _icon.Visible = false;
            _icon.Dispose();
            _dispatcher.Dispose();
        }

        base.Dispose(disposing);
    }

    public void HandleSignal(string message)
    {
        if (string.IsNullOrWhiteSpace(message) || _dispatcher.IsDisposed)
            return;

        void Post(Action action)
        {
            if (_dispatcher.InvokeRequired)
                _dispatcher.BeginInvoke(action);
            else
                action();
        }

        if (!AgentUiSignals.TryNormalize(message, out var signal))
            return;

        switch (signal)
        {
            case AgentUiSignals.Open:
            case AgentUiSignals.Connect:
                RequestHeartbeatBackoffReset(signal == AgentUiSignals.Connect
                    ? "tray_connect_signal"
                    : "tray_open_signal");
                Post(() => _ = OpenAgentAsync());
                break;
            case AgentUiSignals.CheckUpdates:
                Post(() => _ = CheckUpdatesAsync(userInitiated: true));
                break;
            case AgentUiSignals.UpdateNow:
                Post(() => _ = ApplyCheckedUpdateAsync());
                break;
        }
    }

    private async Task RefreshAsync()
    {
        if (_refreshing)
            return;

        _refreshing = true;
        try
        {
            var serviceTask = Task.Run(AgentStatus.GetService);
            var registeredTask = Task.Run(AgentStatus.IsRegistered);
            var tailscaleTask = AgentStatus.GetTailscaleAsync(CancellationToken.None);

            var service = await serviceTask.ConfigureAwait(true);
            var registered = await registeredTask.ConfigureAwait(true);
            var tailscale = await tailscaleTask.ConfigureAwait(true);

            _workspaceStatus.Text = $"{AgentLocalizer.Get("Workspace")}: -";
            _accountStatus.Text = $"{AgentLocalizer.Get("Account")}: -";
            _serviceStatus.Text = AgentLocalizer.Format("ServiceStatus", service.Text);
            _registeredStatus.Text = AgentLocalizer.Format("RegisteredStatus", registered ? AgentLocalizer.Get("Yes") : AgentLocalizer.Get("No"));
            _tailscaleStatus.Text = AgentLocalizer.Format("ConnectorStatus", tailscale.Text);
            _setupComplete = registered &&
                             service.Installed &&
                             string.Equals(service.Text, "running", StringComparison.OrdinalIgnoreCase);
            _connectDevice.Visible = !_setupComplete;
            await RefreshUpdateStateAsync().ConfigureAwait(true);
            _icon.Text = TrimTooltip($"Cerberus Agent | {service.Short} | {tailscale.Short} | reg={(registered ? "yes" : "no")}");
        }
        finally
        {
            _refreshing = false;
        }
    }

    private async Task OpenAgentAsync()
    {
        RequestHeartbeatBackoffReset("tray_opened");
        var setupComplete = _setupComplete || await Task.Run(AgentStatus.IsSetupComplete).ConfigureAwait(true);
        if (!setupComplete)
        {
            LaunchSibling("Cerberus.Agent.Setup.exe");
            return;
        }

        await RefreshAsync().ConfigureAwait(true);
        _icon.ShowBalloonTip(
            3000,
            "Cerberus Agent",
            AgentLocalizer.Get("AgentReadyTrayDetail"),
            ToolTipIcon.Info);
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
        _checkUpdates.Enabled = false;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var response = await AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("check"), timeout.Token).ConfigureAwait(true);
            ApplyUpdateStateToMenu(response);
            if (!response.Success) ShowUpdateMessage(AgentLocalizer.Get("UpdateCheckFailedDetail"));
        }
        catch (Exception)
        {
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateServiceUnavailable"));
            ShowUpdateMessage(AgentLocalizer.Get("UpdateServiceUnavailable"));
        }
        finally
        {
            _checkingUpdates = false;
            _checkUpdates.Enabled = true;
        }
    }

    private async Task ApplyCheckedUpdateAsync(bool consentCaptured = false)
    {
        var displayed = _lastUpdateStatus;
        if (displayed?.AttemptId is null || !AgentUpdateStates.CanApply(displayed.UpdateState))
        {
            ShowUpdateMessage(AgentLocalizer.Get("UpdateCheckRequired"));
            return;
        }
        if (_applyingUpdate || (!consentCaptured && !ConfirmApplyCheckedUpdate())) return;
        _applyingUpdate = true;
        _checkUpdates.Enabled = false;
        _updateNow.Enabled = false;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var response = await AgentLocalControlClient.SendAsync(
                new AgentLocalControlRequest("apply", displayed.AttemptId), timeout.Token).ConfigureAwait(true);
            ApplyUpdateStateToMenu(response);
            if (response.Success)
                _icon.ShowBalloonTip(3000, "Cerberus Agent", AgentLocalizer.Get("UpdateServiceRequestedDetail"), ToolTipIcon.Info);
            else
                ShowUpdateMessage(AgentLocalizer.Get("UpdateInstallFailed"));
        }
        catch (Exception)
        {
            ShowUpdateMessage(AgentLocalizer.Get("UpdateServiceUnavailable"));
        }
        finally
        {
            _applyingUpdate = false;
            _checkUpdates.Enabled = true;
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

    private bool ConfirmApplyCheckedUpdate()
    {
        if (_lastUpdateStatus?.AttemptId is null || !AgentUpdateStates.CanApply(_lastUpdateStatus.UpdateState)) return false;
        return MessageBox.Show(AgentLocalizer.Format("UpdateFoundPrompt", _lastUpdateStatus.TargetVersion ?? "-"),
            AgentLocalizer.Get("UpdateFoundTitle"), MessageBoxButtons.YesNo, MessageBoxIcon.Information,
            MessageBoxDefaultButton.Button2) == DialogResult.Yes;
    }

    private static void RequestHeartbeatBackoffReset(string reason)
        => _ = HeartbeatBackoffResetSignal.TryRequest(reason);

    private static void ShowUpdateMessage(string message, MessageBoxIcon icon = MessageBoxIcon.Warning)
    {
        MessageBox.Show(
            message,
            "Cerberus Agent",
            MessageBoxButtons.OK,
            icon);
    }

    private static void LaunchSibling(string fileName, string? arguments = null)
    {
        var current = Environment.ProcessPath ?? Application.ExecutablePath;
        var dir = Path.GetDirectoryName(current) ?? AppContext.BaseDirectory;
        var path = Path.Combine(dir, fileName);
        if (!File.Exists(path))
            return;

        Process.Start(new ProcessStartInfo
        {
            FileName = path,
            Arguments = arguments ?? "",
            UseShellExecute = true,
        });
    }

    private static void RunServiceAction(Action action)
    {
        try
        {
            action();
        }
        catch
        {
            LaunchSibling("Cerberus.Agent.Setup.exe");
        }
    }

    private static async Task ExportDiagnosticsAsync()
    {
        try
        {
            var path = await AgentDiagnosticsBundle.ExportAsync();
            MessageBox.Show(
                AgentLocalizer.Format("DiagnosticsWritten", path),
                "Cerberus Agent",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                AgentLocalizer.Format("DiagnosticsFailed", AgentDiagnosticsBundle.Redact(ex.Message)),
                "Cerberus Agent",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
    }

    private static string TrimTooltip(string value)
        => value.Length <= 63 ? value : value[..63];
}
