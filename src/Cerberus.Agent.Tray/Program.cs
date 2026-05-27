using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Localization;

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
    private readonly System.Windows.Forms.Timer _timer;
    private bool _refreshing;

    public TrayApplicationContext()
    {
        _workspaceStatus = new ToolStripMenuItem($"{AgentLocalizer.Get("Workspace")}: -") { Enabled = false };
        _accountStatus = new ToolStripMenuItem($"{AgentLocalizer.Get("Account")}: -") { Enabled = false };
        _serviceStatus = new ToolStripMenuItem(AgentLocalizer.Format("ServiceStatus", "...")) { Enabled = false };
        _registeredStatus = new ToolStripMenuItem(AgentLocalizer.Format("RegisteredStatus", "...")) { Enabled = false };
        _tailscaleStatus = new ToolStripMenuItem(AgentLocalizer.Format("ConnectorStatus", "...")) { Enabled = false };

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
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(setup);
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
        _ = RefreshAsync();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _timer.Stop();
            _timer.Dispose();
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
