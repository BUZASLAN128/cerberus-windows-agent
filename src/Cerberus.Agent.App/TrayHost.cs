using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using Cerberus.Agent.Core;
using System.Drawing;
using System.Net.Http;
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
    private const string ServiceName = ServiceInstaller.ServiceName;

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

    public TrayHost()
    {
        _statusHeader = new ToolStripMenuItem("CERBERUS Agent") { Enabled = false };
        _serviceStatus = new ToolStripMenuItem("Service: ...") { Enabled = false };
        _tailscaleStatus = new ToolStripMenuItem("Tailscale: ...") { Enabled = false };
        _registeredStatus = new ToolStripMenuItem("Registered: ...") { Enabled = false };

        var open = new ToolStripMenuItem("Open") { };
        open.Click += (_, _) => ShowWindow();

        _onboard = new ToolStripMenuItem("Sign in and register");
        _onboard.Click += async (_, _) => await OnboardAsync();

        var exportTs = new ToolStripMenuItem("Export tailscale up cmd");
        exportTs.Click += async (_, _) =>
        {
            using var log = AgentFileLogger.CreateDefault(alsoConsole: false);
            try
            {
                var path = await TailscaleUpExporter.ExportAsync(CancellationToken.None);
                if (path is null)
                {
                    // Agent might have been registered when VPN provisioning was temporarily unavailable.
                    // Try to fetch a fresh preauth key and retry export.
                    var cfg = UiConfigStore.LoadMergedWithEnv();
                    var backendUrl = (cfg.BackendUrl ?? "").Trim().TrimEnd('/');
                    if (Uri.TryCreate(backendUrl, UriKind.Absolute, out var backend) &&
                        await TryFetchTailscalePreauthAsync(backend, CancellationToken.None))
                    {
                        path = await TailscaleUpExporter.ExportAsync(CancellationToken.None);
                    }
                }
                if (path is null)
                {
                    ShowBalloon("VPN", "VPN provisioning is not available. Contact your administrator.", ToolTipIcon.Warning);
                    return;
                }
                ShowBalloon("VPN", $"Wrote: {path}", ToolTipIcon.Info);
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
        _startService.Click += (_, _) => StartService();

        _stopService = new ToolStripMenuItem("Stop service");
        _stopService.Click += (_, _) => StopService();

        _installService = new ToolStripMenuItem("Install service");
        _installService.Click += (_, _) =>
        {
            if (!Elevation.IsAdministrator())
            {
                if (Elevation.TryRunElevated("--install-service"))
                    ShowBalloon("Service", "UAC prompt opened for install.", ToolTipIcon.Info);
                return;
            }

            try
            {
                ServiceInstaller.InstallOrThrow();
                ShowBalloon("Service", "Installed and started.", ToolTipIcon.Info);
            }
            catch (Exception ex)
            {
                ShowBalloon("Service", ex.Message, ToolTipIcon.Error);
            }
        };

        _uninstallService = new ToolStripMenuItem("Uninstall service");
        _uninstallService.Click += (_, _) =>
        {
            if (!Elevation.IsAdministrator())
            {
                if (Elevation.TryRunElevated("--uninstall-service"))
                    ShowBalloon("Service", "UAC prompt opened for uninstall.", ToolTipIcon.Info);
                return;
            }

            try
            {
                ServiceInstaller.UninstallOrThrow();
                ShowBalloon("Service", "Uninstalled.", ToolTipIcon.Info);
            }
            catch (Exception ex)
            {
                ShowBalloon("Service", ex.Message, ToolTipIcon.Error);
            }
        };

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
                ShowWindow();
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

        _serviceStatus.Text = $"Service: {svc.Text}";
        _tailscaleStatus.Text = $"Tailscale: {ts.Text}";
        _registeredStatus.Text = $"Registered: {(registered ? "yes" : "no")}";

        var cfg = UiConfigStore.LoadMergedWithEnv();
        var cfgOk = IsConfigReadyForOnboarding(cfg);
        _onboard.Enabled = !_onboarding && !registered && cfgOk;
        _startService.Enabled = svc.CanStart;
        _stopService.Enabled = svc.CanStop;
        _installService.Enabled = !svc.Installed;
        _uninstallService.Enabled = svc.Installed;

        _icon.Text = TrimTooltip($"CERBERUS Agent | {svc.Short} | {ts.Short} | reg={(registered ? "yes" : "no")}");
    }

    private void ShowWindow()
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
                _window.Hide();
                return;
            }

            // Prevent immediate auto-hide caused by transient focus changes during Show/Position/Activate.
            _window.SetIgnoreDeactivateFor(TimeSpan.FromMilliseconds(900));

            _window.Show();
            PositionFlyout(_window);

            _window.WindowState = WindowState.Normal;
            _window.Activate();
            _window.Topmost = true; // bring to front reliably
            _window.Topmost = false;
            _window.Focus();
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

    private static async Task<bool> TryFetchTailscalePreauthAsync(Uri backend, CancellationToken ct)
    {
        try
        {
            // Best-effort: if the device is registered, use agent auth to request a fresh
            // VPN preauth key (single-use) and persist it for export/service usage.
            var secrets = new DpapiSecretStore(SecretStoreScope.User);
            var (_, _, privateKeyPem, _, _, _) = await secrets.LoadAsync(ct);

            using var http = new HttpClient { BaseAddress = backend, Timeout = TimeSpan.FromSeconds(30) };
            var tokens = new AgentTokenManager(http, secrets);
            var signer = new RequestSigner(privateKeyPem);
            var api = new AgentApiClient(http, secrets, tokens, signer);

            var (loginServer, authKey) = await api.GetTailscalePreauthAsync(ct);

            // Rotation-safe: reload secrets to avoid overwriting a newly rotated refresh token.
            var (id2, refresh2, priv2, backendUrl2, _, _) = await secrets.LoadAsync(ct);
            await secrets.SaveAsync(id2, refresh2, priv2, backendUrl2, loginServer, authKey, ct);

            return true;
        }
        catch
        {
            return false;
        }
    }

    private async Task OnboardAsync()
    {
        if (_onboarding)
            return;
        if (AgentStatus.IsRegistered())
        {
            ShowBalloon("Sign-in", "Already registered. Use Open for details.", ToolTipIcon.Info);
            return;
        }

        _onboarding = true;
        try
        {
            await RefreshAsync();

            using var log = AgentFileLogger.CreateDefault(alsoConsole: false);

            var cfg = UiConfigStore.LoadMergedWithEnv();

            var backendUrl = cfg.BackendUrl.Trim().TrimEnd('/');
            if (!Uri.TryCreate(backendUrl, UriKind.Absolute, out var backend))
            {
                ShowBalloon("Sign-in", "Not configured. Contact your administrator.", ToolTipIcon.Error);
                return;
            }

            var casdoorEndpoint = cfg.CasdoorEndpoint.Trim().TrimEnd('/');
            if (string.IsNullOrWhiteSpace(casdoorEndpoint) || !Uri.TryCreate(casdoorEndpoint, UriKind.Absolute, out var casdoorBase))
            {
                ShowBalloon("Sign-in", "Not configured. Contact your administrator.", ToolTipIcon.Error);
                return;
            }

            var clientId = cfg.CasdoorClientId.Trim();
            if (string.IsNullOrWhiteSpace(clientId))
            {
                ShowBalloon("Sign-in", "Not configured. Contact your administrator.", ToolTipIcon.Error);
                return;
            }

            var clientSecret = cfg.CasdoorClientSecret;
            var scope = cfg.CasdoorScope;
            var redirectPort = cfg.OAuthRedirectPort;

            ShowBalloon("Sign-in", "Opening browser for SSO sign-in...", ToolTipIcon.Info);
            var oauth = new CasdoorOAuthClient(
                casdoorBase,
                clientId,
                string.IsNullOrWhiteSpace(clientSecret) ? null : clientSecret,
                scope);
            var token = await oauth.LoginWithPkceAsync(redirectPort, CancellationToken.None);

            using var http = new HttpClient { BaseAddress = backend, Timeout = TimeSpan.FromSeconds(30) };
            var secrets = new DpapiSecretStore(SecretStoreScope.User);
            var registrar = new AgentRegistrar(http, secrets, keyPairs: null, log: log);

            var identity = await registrar.RegisterAsync(
                token.AccessToken,
                backendUrlForStorage: backendUrl,
                deviceFingerprint: WindowsDeviceInfo.ComputeDeviceFingerprint(),
                agentVersion: WindowsDeviceInfo.GetAgentVersion(),
                ct: CancellationToken.None);

            var cmdPath = await TailscaleUpExporter.ExportAsync(CancellationToken.None);
            if (cmdPath is not null)
                ShowBalloon("Sign-in", $"Registered. Wrote tailscale cmd: {cmdPath}", ToolTipIcon.Info);
            else
                ShowBalloon("Sign-in", $"Registered. (No tailscale cmd.)", ToolTipIcon.Info);
        }
        catch (Exception ex)
        {
            ShowBalloon("Sign-in", Sanitizer.Redact(ex.Message), ToolTipIcon.Error);
        }
        finally
        {
            _onboarding = false;
            await RefreshAsync();
        }
    }

    private static bool IsConfigReadyForOnboarding(RuntimeUiConfig cfg)
    {
        var backendUrl = (cfg.BackendUrl ?? "").Trim().TrimEnd('/');
        if (!Uri.TryCreate(backendUrl, UriKind.Absolute, out _))
            return false;

        var ssoBase = (cfg.CasdoorEndpoint ?? "").Trim().TrimEnd('/');
        if (!Uri.TryCreate(ssoBase, UriKind.Absolute, out _))
            return false;

        if (string.IsNullOrWhiteSpace(cfg.CasdoorClientId))
            return false;

        return true;
    }

    private void StartService()
    {
        if (!Elevation.IsAdministrator())
        {
            if (Elevation.TryRunElevated("--start-service"))
                ShowBalloon("Service", "UAC prompt opened to start service.", ToolTipIcon.Info);
            return;
        }

        try
        {
            ServiceInstaller.StartOrThrow();
            ShowBalloon("Service", "Started.", ToolTipIcon.Info);
        }
        catch (Exception ex)
        {
            ShowBalloon("Service", ex.Message, ToolTipIcon.Error);
        }
    }

    private void StopService()
    {
        if (!Elevation.IsAdministrator())
        {
            if (Elevation.TryRunElevated("--stop-service"))
                ShowBalloon("Service", "UAC prompt opened to stop service.", ToolTipIcon.Info);
            return;
        }

        try
        {
            ServiceInstaller.StopOrThrow();
            ShowBalloon("Service", "Stopped.", ToolTipIcon.Info);
        }
        catch (Exception ex)
        {
            ShowBalloon("Service", ex.Message, ToolTipIcon.Error);
        }
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
