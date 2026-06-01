using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Localization;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Tray;

internal static class Program
{
    private const string TrayMutexName = "Global\\CerberusAgent.Tray.SingleInstance";
    private const string TrayPipeName = "CerberusAgent.Tray.SingleInstancePipe";
    private const string OpenSignal = "open";
    private const string ConnectSignal = "connect";
    private const string CheckUpdatesSignal = "check-updates";
    private const string UpdateNowSignal = "update-now";

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
            return OpenSignal;
        if (Has("--connect") || Has("/connect"))
            return ConnectSignal;
        if (Has("--check-updates") || Has("/check-updates"))
            return CheckUpdatesSignal;
        if (Has("--update-now") || Has("/update-now"))
            return UpdateNowSignal;
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
    private readonly ToolStripMenuItem _updateNow;
    private readonly AgentUpdateStateStore _updateStateStore;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly System.Windows.Forms.Timer _startupUpdateTimer;
    private readonly Control _dispatcher;
    private bool _refreshing;
    private bool _setupComplete;
    private bool _checkingUpdates;
    private bool _applyingUpdate;
    private AgentUpdateSignal? _lastCheckedUpdateSignal;
    private AgentUpdateCheckResult? _lastUpdateCheck;
    private string? _lastPromptedUpdateKey;

    public TrayApplicationContext()
    {
        _updateStateStore = AgentUpdateStateStore.CreateDefault();
        _dispatcher = new Control();
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
        _connectDevice.Click += (_, _) => _ = OpenAgentAsync();

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

        _ = RefreshAsync();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
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

        switch (message.Trim().ToLowerInvariant())
        {
            case "open":
            case "connect":
                Post(() => _ = OpenAgentAsync());
                break;
            case "check-updates":
                Post(() => _ = CheckUpdatesAsync(userInitiated: true));
                break;
            case "update-now":
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
        if (_checkingUpdates || _applyingUpdate)
            return;

        _checkingUpdates = true;
        _checkUpdates.Enabled = false;
        _updateNow.Enabled = false;
        _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateChecking"));
        await _updateStateStore.WriteTransitionAsync(
            AgentUpdateStates.Checking,
            WindowsDeviceInfo.GetAgentVersion(),
            CancellationToken.None).ConfigureAwait(true);

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            using var updateHttp = CreateUpdateHttpClient();
            var coordinator = AgentUpdateTrustFactory.BuildCoordinator(updateHttp, NullAgentLogger.Instance, _updateStateStore);
            var signal = AgentUpdateTrustFactory.BuildConfiguredManualSignal();
            if (coordinator is null || signal is null)
            {
                await _updateStateStore.WriteTransitionAsync(
                    AgentUpdateStates.Failed,
                    WindowsDeviceInfo.GetAgentVersion(),
                    CancellationToken.None,
                    errorCode: AgentUpdateErrorCodes.NotConfigured,
                    errorMessage: "Update trust is not configured.",
                    markChecked: true).ConfigureAwait(true);
                ClearCheckedUpdate(AgentLocalizer.Get("UpdateUnavailable"));
                if (userInitiated)
                    ShowUpdateMessage(AgentLocalizer.Get("UpdateNotConfiguredDetail"));
                return;
            }

            var check = await coordinator.CheckUpdateAsync(signal, cts.Token).ConfigureAwait(true);
            if (!check.Available)
            {
                await _updateStateStore.WriteTransitionAsync(
                    AgentUpdateStates.Current,
                    WindowsDeviceInfo.GetAgentVersion(),
                    CancellationToken.None,
                    channel: signal.Channel,
                    manifestUrl: signal.ManifestUrl,
                    markChecked: true).ConfigureAwait(true);
                ClearCheckedUpdate(AgentLocalizer.Get("UpdateCurrent"));
                return;
            }

            _lastCheckedUpdateSignal = signal;
            _lastUpdateCheck = check;
            await _updateStateStore.WriteTransitionAsync(
                AgentUpdateStates.Available,
                WindowsDeviceInfo.GetAgentVersion(),
                CancellationToken.None,
                targetVersion: check.Version,
                channel: check.Channel ?? signal.Channel,
                manifestUrl: check.ManifestUrl ?? signal.ManifestUrl,
                markChecked: true).ConfigureAwait(true);
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Format("UpdateAvailable", check.Version ?? "-"));
            _updateNow.Enabled = true;
        }
        catch
        {
            await _updateStateStore.WriteTransitionAsync(
                AgentUpdateStates.Failed,
                WindowsDeviceInfo.GetAgentVersion(),
                CancellationToken.None,
                errorCode: AgentUpdateErrorCodes.ManifestUnavailable,
                errorMessage: "Update check failed.",
                markChecked: true).ConfigureAwait(true);
            ClearCheckedUpdate(AgentLocalizer.Get("UpdateCheckFailed"));
            if (userInitiated)
                ShowUpdateMessage(GetUpdateCheckFailureDetail());
        }
        finally
        {
            _checkingUpdates = false;
            _checkUpdates.Enabled = true;
        }
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
        _checkUpdates.Enabled = false;
        _updateNow.Enabled = false;
        _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateInstalling"));

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(15));
            using var updateHttp = CreateUpdateHttpClient();
            var coordinator = AgentUpdateTrustFactory.BuildCoordinator(updateHttp, NullAgentLogger.Instance, _updateStateStore)
                               ?? throw new InvalidOperationException("Update trust is not configured.");
            var launched = await coordinator
                .StageAndLaunchUpdateAsync(_lastCheckedUpdateSignal, requireElevation: true, ct: cts.Token)
                .ConfigureAwait(true);
            if (!launched)
            {
                ClearCheckedUpdate(AgentLocalizer.Get("UpdateCurrent"));
                return;
            }

            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateInstallerStarted"));
            _lastCheckedUpdateSignal = null;
            _lastUpdateCheck = null;
        }
        catch (Exception ex)
        {
            await _updateStateStore.WriteTransitionAsync(
                AgentUpdateStates.Failed,
                WindowsDeviceInfo.GetAgentVersion(),
                CancellationToken.None,
                targetVersion: _lastUpdateCheck?.Version,
                channel: _lastUpdateCheck?.Channel,
                manifestUrl: _lastUpdateCheck?.ManifestUrl,
                errorCode: AgentUpdateErrorCodes.Classify(ex),
                errorMessage: AgentDiagnosticsBundle.Redact(ex.Message)).ConfigureAwait(true);
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateInstallFailed"));
            MessageBox.Show(
                AgentLocalizer.Format("UpdateInstallFailedDetail", AgentDiagnosticsBundle.Redact(ex.Message)),
                "Cerberus Agent",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            _updateNow.Enabled = _lastUpdateCheck?.Available == true;
        }
        finally
        {
            _applyingUpdate = false;
            _checkUpdates.Enabled = true;
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
        if (_lastUpdateCheck?.Available != true)
            return;

        var version = string.IsNullOrWhiteSpace(_lastUpdateCheck.Version)
            ? "-"
            : _lastUpdateCheck.Version;
        var result = MessageBox.Show(
            AgentLocalizer.Format("UpdateFoundPrompt", version),
            AgentLocalizer.Get("UpdateFoundTitle"),
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Information,
            MessageBoxDefaultButton.Button2);
        if (result == DialogResult.Yes)
            await ApplyCheckedUpdateAsync().ConfigureAwait(true);
    }

    private static string StateLabel(AgentUpdateState state)
        => state.State switch
        {
            AgentUpdateStates.NotChecked => AgentLocalizer.Get("UpdateNotChecked"),
            AgentUpdateStates.Checking => AgentLocalizer.Get("UpdateChecking"),
            AgentUpdateStates.Current => AgentLocalizer.Get("UpdateCurrent"),
            AgentUpdateStates.Available => AgentLocalizer.Format("UpdateAvailable", state.TargetVersion ?? "-"),
            AgentUpdateStates.Downloading => AgentLocalizer.Get("UpdateChecking"),
            AgentUpdateStates.Staged => AgentLocalizer.Format("UpdateAvailable", state.TargetVersion ?? "-"),
            AgentUpdateStates.Prompting => AgentLocalizer.Format("UpdateAvailable", state.TargetVersion ?? "-"),
            AgentUpdateStates.Applying => AgentLocalizer.Get("UpdateInstalling"),
            AgentUpdateStates.InstallerStarted => AgentLocalizer.Get("UpdateInstallerStarted"),
            AgentUpdateStates.Applied => AgentLocalizer.Get("UpdateCurrent"),
            AgentUpdateStates.Failed => AgentLocalizer.Get("UpdateCheckFailed"),
            _ => AgentLocalizer.Get("UpdateNotChecked"),
        };

    private static HttpClient CreateUpdateHttpClient()
        => new()
        {
            Timeout = TimeSpan.FromMinutes(10),
        };

    private static string GetUpdateCheckFailureDetail()
        => AgentLocalizer.Get("UpdateCheckFailedDetail");

    private static void ShowUpdateMessage(string message)
    {
        MessageBox.Show(
            message,
            "Cerberus Agent",
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
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
