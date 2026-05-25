using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using Cerberus.Agent.App;

namespace Cerberus.Agent.Tray;

internal static class Program
{
    [STAThread]
    public static void Main()
    {
        ApplicationConfiguration.Initialize();
        using var tray = new TrayApplicationContext();
        Application.Run(tray);
    }
}

internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _serviceStatus;
    private readonly ToolStripMenuItem _registeredStatus;
    private readonly ToolStripMenuItem _tailscaleStatus;
    private readonly System.Windows.Forms.Timer _timer;
    private bool _refreshing;

    public TrayApplicationContext()
    {
        _serviceStatus = new ToolStripMenuItem("Service: ...") { Enabled = false };
        _registeredStatus = new ToolStripMenuItem("Registered: ...") { Enabled = false };
        _tailscaleStatus = new ToolStripMenuItem("Tailscale: ...") { Enabled = false };

        var setup = new ToolStripMenuItem("Open setup");
        setup.Click += (_, _) => LaunchSibling("Cerberus.Agent.Setup.exe");

        var startService = new ToolStripMenuItem("Start service");
        startService.Click += (_, _) => RunServiceAction(ServiceInstaller.StartOrThrow);

        var stopService = new ToolStripMenuItem("Stop service");
        stopService.Click += (_, _) => RunServiceAction(ServiceInstaller.StopOrThrow);

        var exit = new ToolStripMenuItem("Exit");
        exit.Click += (_, _) => ExitThread();

        var menu = new ContextMenuStrip();
        menu.Items.Add(new ToolStripMenuItem("CERBERUS Agent") { Enabled = false });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_serviceStatus);
        menu.Items.Add(_registeredStatus);
        menu.Items.Add(_tailscaleStatus);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(setup);
        menu.Items.Add(startService);
        menu.Items.Add(stopService);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exit);

        _icon = new NotifyIcon
        {
            Icon = SystemIcons.Application,
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

            _serviceStatus.Text = $"Service: {service.Text}";
            _registeredStatus.Text = $"Registered: {(registered ? "yes" : "no")}";
            _tailscaleStatus.Text = $"Tailscale: {tailscale.Text}";
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

    private static string TrimTooltip(string value)
        => value.Length <= 63 ? value : value[..63];
}
