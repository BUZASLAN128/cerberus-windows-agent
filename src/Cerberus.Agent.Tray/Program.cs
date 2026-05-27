using System.Diagnostics;
using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Localization;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.Tray;

internal static class Program
{
    private const string TrayMutexName = "Global\\CerberusAgent.Tray.SingleInstance";
    private const string TrayPipeName = "CerberusAgent.Tray.SingleInstancePipe";

    [STAThread]
    public static void Main()
    {
        AgentLocalizer.ApplyThreadCulture();
        if (!ProcessInstanceGuard.TryAcquire(TrayMutexName, TrayPipeName, null, out var instanceGuard))
            return;

        ApplicationConfiguration.Initialize();
        using (instanceGuard)
        using (var tray = new TrayApplicationContext())
        {
            Application.Run(tray);
        }
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
    private readonly ToolStripMenuItem _checkUpdates;
    private readonly ToolStripMenuItem _updateNow;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly System.Windows.Forms.Timer _startupUpdateTimer;
    private bool _refreshing;
    private bool _checkingUpdates;
    private bool _applyingUpdate;
    private HeartbeatResponse? _lastCheckedUpdateResponse;
    private AgentUpdateCheckResult? _lastUpdateCheck;

    public TrayApplicationContext()
    {
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

        var setup = new ToolStripMenuItem(AgentLocalizer.Get("OpenSetup"));
        setup.Click += (_, _) => LaunchSibling("Cerberus.Agent.Setup.exe");

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
        menu.Items.Add(new ToolStripMenuItem("CERBERUS Agent") { Enabled = false });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_workspaceStatus);
        menu.Items.Add(_accountStatus);
        menu.Items.Add(_serviceStatus);
        menu.Items.Add(_registeredStatus);
        menu.Items.Add(_tailscaleStatus);
        menu.Items.Add(_updateStatus);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(setup);
        menu.Items.Add(_checkUpdates);
        menu.Items.Add(_updateNow);
        menu.Items.Add(diagnostics);
        menu.Items.Add(repair);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exit);

        _icon = new NotifyIcon
        {
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application,
            Text = "CERBERUS Agent",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
                LaunchSibling("Cerberus.Agent.Setup.exe");
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
        }

        base.Dispose(disposing);
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
            _icon.Text = TrimTooltip($"CERBERUS Agent | {service.Short} | {tailscale.Short} | reg={(registered ? "yes" : "no")}");
        }
        finally
        {
            _refreshing = false;
        }
    }

    private async Task CheckUpdatesAsync(bool userInitiated)
    {
        if (_checkingUpdates || _applyingUpdate)
            return;

        _checkingUpdates = true;
        _checkUpdates.Enabled = false;
        _updateNow.Enabled = false;
        _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateChecking"));

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            var heartbeat = await SendUpdateCheckHeartbeatAsync(cts.Token).ConfigureAwait(true);
            using var updateHttp = await CreateUpdateHttpClientAsync(cts.Token).ConfigureAwait(true);
            var coordinator = AgentUpdateTrustFactory.BuildCoordinator(updateHttp, NullAgentLogger.Instance);
            if (coordinator is null)
            {
                ClearCheckedUpdate(AgentLocalizer.Get("UpdateUnavailable"));
                return;
            }

            var check = await coordinator.CheckUpdateAsync(heartbeat, cts.Token).ConfigureAwait(true);
            if (!check.Available)
            {
                ClearCheckedUpdate(AgentLocalizer.Get("UpdateCurrent"));
                return;
            }

            _lastCheckedUpdateResponse = heartbeat;
            _lastUpdateCheck = check;
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Format("UpdateAvailable", check.Version ?? "-"));
            _updateNow.Enabled = true;
        }
        catch (Exception ex)
        {
            ClearCheckedUpdate(AgentLocalizer.Get("UpdateCheckFailed"));
            if (userInitiated)
            {
                MessageBox.Show(
                    AgentLocalizer.Format("UpdateCheckFailedDetail", AgentDiagnosticsBundle.Redact(ex.Message)),
                    "CERBERUS Agent",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
        }
        finally
        {
            _checkingUpdates = false;
            _checkUpdates.Enabled = true;
        }
    }

    private async Task ApplyCheckedUpdateAsync()
    {
        if (_lastCheckedUpdateResponse is null || _lastUpdateCheck is null || !_lastUpdateCheck.Available)
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
            using var updateHttp = await CreateUpdateHttpClientAsync(cts.Token).ConfigureAwait(true);
            var coordinator = AgentUpdateTrustFactory.BuildCoordinator(updateHttp, NullAgentLogger.Instance)
                              ?? throw new InvalidOperationException("Update trust is not configured.");
            await coordinator
                .StageAndLaunchUpdateAsync(_lastCheckedUpdateResponse, requireElevation: true, ct: cts.Token)
                .ConfigureAwait(true);
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateInstallerStarted"));
            _lastCheckedUpdateResponse = null;
            _lastUpdateCheck = null;
        }
        catch (Exception ex)
        {
            _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", AgentLocalizer.Get("UpdateInstallFailed"));
            MessageBox.Show(
                AgentLocalizer.Format("UpdateInstallFailedDetail", AgentDiagnosticsBundle.Redact(ex.Message)),
                "CERBERUS Agent",
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
        _lastCheckedUpdateResponse = null;
        _lastUpdateCheck = null;
        _updateNow.Enabled = false;
        _updateStatus.Text = AgentLocalizer.Format("UpdateStatus", status);
    }

    private static async Task<HeartbeatResponse> SendUpdateCheckHeartbeatAsync(CancellationToken ct)
    {
        var (secrets, privateKeyPem, backend) = await LoadUpdateSecretsAsync(ct).ConfigureAwait(false);

        using var http = new HttpClient { BaseAddress = backend, Timeout = TimeSpan.FromSeconds(30) };
        var api = new AgentApiClient(
            http,
            secrets,
            new AgentTokenManager(http, secrets),
            new RequestSigner(privateKeyPem));
        var metadata = new AgentBuildMetadata(
            AgentVersion: WindowsDeviceInfo.GetAgentVersion(),
            BuildId: WindowsDeviceInfo.GetBuildId(),
            BuildChannel: WindowsDeviceInfo.GetBuildChannel(),
            BootId: Guid.NewGuid().ToString("N"),
            SupportedSchemaVersions: AgentSchemaVersions.All);

        return await api.HeartbeatAsync(new
        {
            status = "connected",
            agent_version = metadata.AgentVersion,
            build_id = metadata.BuildId,
            build_channel = metadata.BuildChannel,
            runtime_mode = "tray_update_check",
            supported_schema_versions = metadata.SupportedSchemaVersions,
            capabilities = Array.Empty<string>(),
        }, ct).ConfigureAwait(false);
    }

    private static async Task<HttpClient> CreateUpdateHttpClientAsync(CancellationToken ct)
    {
        var (_, _, backend) = await LoadUpdateSecretsAsync(ct).ConfigureAwait(false);

        return new HttpClient
        {
            BaseAddress = backend,
            Timeout = TimeSpan.FromMinutes(10),
        };
    }

    private static async Task<(DpapiSecretStore Store, string PrivateKeyPem, Uri Backend)> LoadUpdateSecretsAsync(CancellationToken ct)
    {
        foreach (var scope in new[] { SecretStoreScope.User, SecretStoreScope.Machine })
        {
            try
            {
                var secrets = new DpapiSecretStore(scope);
                var (_, _, privateKeyPem, storedBackendUrl, _, _) = await secrets.LoadAsync(ct).ConfigureAwait(false);
                var backendUrl = (Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL") ?? storedBackendUrl).Trim().TrimEnd('/');
                if (!Uri.TryCreate(backendUrl, UriKind.Absolute, out var backend))
                    throw new InvalidOperationException("Stored backend URL is invalid.");

                return (secrets, privateKeyPem, backend);
            }
            catch (Exception ex) when (IsUpdateSecretFallbackError(ex))
            {
                // Try the next supported scope. User scope is preferred for tray UX; machine scope
                // remains available for elevated repair/admin paths and older enrollments.
            }
        }

        throw new InvalidOperationException("Agent registration is not available for update checks.");
    }

    private static bool IsUpdateSecretFallbackError(Exception ex)
        => ex is FileNotFoundException
            or DirectoryNotFoundException
            or UnauthorizedAccessException
            or CryptographicException
            or InvalidOperationException;

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
                "CERBERUS Agent",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                AgentLocalizer.Format("DiagnosticsFailed", AgentDiagnosticsBundle.Redact(ex.Message)),
                "CERBERUS Agent",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
    }

    private static string TrimTooltip(string value)
        => value.Length <= 63 ? value : value[..63];
}
