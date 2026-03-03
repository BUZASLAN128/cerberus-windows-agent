using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Threading;

namespace Cerberus.Agent.App;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer;
    private volatile bool _busy;
    private DateTimeOffset _ignoreDeactivateUntil = DateTimeOffset.MinValue;
    private RuntimeUiConfig _config;

    public MainWindow()
    {
        InitializeComponent();

        _config = UiConfigStore.LoadMergedWithEnv();

        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(5),
        };
        _timer.Tick += async (_, _) => await RefreshAsync();

        Loaded += async (_, _) =>
        {
            await RefreshAsync();
            _timer.Start();
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
        var ts = DateTimeOffset.Now.ToString("HH:mm:ss");
        StatusText.AppendText($"[{ts}] {msg}\r\n");
        StatusText.ScrollToEnd();
    }

    private async Task RefreshAsync()
    {
        _config = UiConfigStore.LoadMergedWithEnv();

        // IMPORTANT: Keep the UI responsive. ServiceController calls can block; run off-thread.
        var svcTask = Task.Run(AgentStatus.GetService);
        var registeredTask = Task.Run(AgentStatus.IsRegistered);
        var tsTask = AgentStatus.GetTailscaleAsync(CancellationToken.None);

        var svc = await svcTask;
        var registered = await registeredTask;
        var ts = await tsTask;

        ServiceValue.Text = svc.Text;
        TailscaleValue.Text = ts.Text;
        RegisteredValue.Text = registered ? "yes" : "no";

        var cfgOk = IsConfigReadyForOnboarding(_config);
        OnboardBtn.IsEnabled = !_busy && !registered && cfgOk;
        if (registered)
        {
            OnboardHint.Text = "Already registered.";
        }
        else if (!cfgOk)
        {
            OnboardHint.Text = "Not configured. Contact your administrator.";
        }
        else
        {
            OnboardHint.Text = "Not registered yet.";
        }

        InstallSvcBtn.IsEnabled = !_busy && !svc.Installed;
        UninstallSvcBtn.IsEnabled = !_busy && svc.Installed;
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
            : (File.Exists(machineCmdPath) ? machineCmdPath : "cmd not exported yet");
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

    private async void Onboard_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
            return;
        if (AgentStatus.IsRegistered())
        {
            Log("Already registered.");
            await RefreshAsync();
            return;
        }

        _busy = true;
        try
        {
            await RefreshAsync();
            Log("Starting SSO sign-in (browser will open)...");

            _config = UiConfigStore.LoadMergedWithEnv();
            if (!IsConfigReadyForOnboarding(_config))
            {
                System.Windows.MessageBox.Show(
                    this,
                    "This device is not configured for onboarding.\n\nPlease contact your administrator.",
                    "Not Configured",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                Log("Onboarding blocked: missing configuration.");
                return;
            }

            var backendUrl = _config.BackendUrl.Trim().TrimEnd('/');
            var backend = new Uri(backendUrl);
            var ssoBaseUrl = _config.CasdoorEndpoint.Trim().TrimEnd('/');
            var ssoBase = new Uri(ssoBaseUrl);

            var clientId = _config.CasdoorClientId.Trim();
            var clientSecret = _config.CasdoorClientSecret;
            var scope = _config.CasdoorScope;
            var redirectPort = _config.OAuthRedirectPort;

            var oauth = new CasdoorOAuthClient(
                ssoBase,
                clientId,
                string.IsNullOrWhiteSpace(clientSecret) ? null : clientSecret,
                scope);
            var token = await oauth.LoginWithPkceAsync(redirectPort, CancellationToken.None);

            Log("Login ok. Registering agent...");

            using var log = AgentFileLogger.CreateDefault(alsoConsole: false);
            using var http = new HttpClient { BaseAddress = backend, Timeout = TimeSpan.FromSeconds(30) };
            var secrets = new DpapiSecretStore(SecretStoreScope.User);
            var registrar = new AgentRegistrar(http, secrets, keyPairs: null, log: log);

            var identity = await registrar.RegisterAsync(
                token.AccessToken,
                backendUrlForStorage: backendUrl,
                deviceFingerprint: WindowsDeviceInfo.ComputeDeviceFingerprint(),
                agentVersion: WindowsDeviceInfo.GetAgentVersion(),
                ct: CancellationToken.None);

            Log($"Registered. agent_id={identity.AgentId} tenant_id={identity.TenantId}");

            var cmdPath = await TailscaleUpExporter.ExportAsync(CancellationToken.None);
            if (cmdPath is null)
            {
                // Register tries to create a preauth key, but Headscale may be configured later or
                // temporarily unavailable. Try once more via the dedicated endpoint.
                if (await TryFetchTailscalePreauthAsync(backend, CancellationToken.None))
                    cmdPath = await TailscaleUpExporter.ExportAsync(CancellationToken.None);
            }

            if (cmdPath is not null)
                Log($"Wrote tailscale up cmd: {cmdPath}");
            else
                Log("No tailscale cmd exported.");
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

    private void InstallSvc_Click(object sender, RoutedEventArgs e)
    {
        if (!Elevation.IsAdministrator())
        {
            Elevation.TryRunElevated("--install-service");
            Log("Requested elevation for install.");
            return;
        }

        try
        {
            ServiceInstaller.InstallOrThrow();
            Log("Service installed and started.");
        }
        catch (Exception ex)
        {
            Log($"Install failed: {ex.Message}");
        }
    }

    private void UninstallSvc_Click(object sender, RoutedEventArgs e)
    {
        if (!Elevation.IsAdministrator())
        {
            Elevation.TryRunElevated("--uninstall-service");
            Log("Requested elevation for uninstall.");
            return;
        }

        try
        {
            ServiceInstaller.UninstallOrThrow();
            Log("Service uninstalled.");
        }
        catch (Exception ex)
        {
            Log($"Uninstall failed: {ex.Message}");
        }
    }

    private void StartSvc_Click(object sender, RoutedEventArgs e)
    {
        if (!Elevation.IsAdministrator())
        {
            Elevation.TryRunElevated("--start-service");
            Log("Requested elevation for start.");
            return;
        }

        try
        {
            ServiceInstaller.StartOrThrow();
            Log("Service started.");
        }
        catch (Exception ex)
        {
            Log($"Start failed: {ex.Message}");
        }
    }

    private void StopSvc_Click(object sender, RoutedEventArgs e)
    {
        if (!Elevation.IsAdministrator())
        {
            Elevation.TryRunElevated("--stop-service");
            Log("Requested elevation for stop.");
            return;
        }

        try
        {
            ServiceInstaller.StopOrThrow();
            Log("Service stopped.");
        }
        catch (Exception ex)
        {
            Log($"Stop failed: {ex.Message}");
        }
    }

    private async void ExportTs_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = await TailscaleUpExporter.ExportAsync(CancellationToken.None);
            if (path is null)
            {
                // Try to fetch preauth after-the-fact (agent already registered).
                var backendUrl = _config.BackendUrl.Trim().TrimEnd('/');
                if (Uri.TryCreate(backendUrl, UriKind.Absolute, out var backend) &&
                    await TryFetchTailscalePreauthAsync(backend, CancellationToken.None))
                {
                    path = await TailscaleUpExporter.ExportAsync(CancellationToken.None);
                }

                if (path is null)
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
            }

            if (path is not null)
            {
                TsCmdPathLabel.Text = path;
                Log($"Wrote cmd: {path}");
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

    private async Task<bool> TryFetchTailscalePreauthAsync(Uri backend, CancellationToken ct)
    {
        try
        {
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

            Log("Fetched VPN preauth key.");
            return true;
        }
        catch (FileNotFoundException)
        {
            // Not registered yet.
            return false;
        }
        catch (Exception ex)
        {
            Log($"Preauth fetch failed: {Sanitizer.Redact(ex.Message)}");
            return false;
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
