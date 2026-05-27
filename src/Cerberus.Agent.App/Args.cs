namespace Cerberus.Agent.App;

internal sealed record AgentArgs(
    bool Service,
    bool InstallService,
    bool UninstallService,
    bool UnregisterDevice,
    bool StartService,
    bool StopService,
    bool AcceptEula,
    bool Setup,
    bool Register,
    bool HeartbeatOnce,
    bool ExportTailscaleUp,
    bool SelfTest,
    bool SelfTestJson,
    string? SelfTestOutFile,
    string? CasdoorTokenFile,
    string? ApplyUpdatePlan,
    string? ApplyUpdateTarget);

internal static class Args
{
    public static AgentArgs Parse(string[] args)
    {
        bool Has(string a) => args.Any(x => string.Equals(x, a, StringComparison.OrdinalIgnoreCase));

        string? Value(string key)
        {
            for (var i = 0; i < args.Length; i++)
            {
                var a = args[i];
                if (a is null)
                    continue;

                if (a.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                    return a[(key.Length + 1)..].Trim('"');

                if (string.Equals(a, key, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    return args[i + 1].Trim('"');
            }

            return null;
        }

        var service = Has("--service");
        var install = Has("--install-service");
        var uninstall = Has("--uninstall-service");
        var unregisterDevice = Has("--unregister-device") || Has("--factory-reset");
        var startService = Has("--start-service");
        var stopService = Has("--stop-service");
        var acceptEula = Has("--accept-eula") || Has("--accept-license");
        var setup = Has("--setup") || Has("--install-agent") || Has("--onboard");
        var register = Has("--register");
        var heartbeatOnce = Has("--heartbeat-once");
        var exportTailscaleUp = Has("--export-tailscale-up");
        var selfTest = Has("--self-test");
        var selfTestJson = Has("--self-test-json") || Has("--json");
        var selfTestOutFile = Value("--self-test-out");
        var casdoorTokenFile = Value("--casdoor-token-file") ?? Value("--token-file");
        var applyUpdatePlan = Value("--apply-staged-update");
        var applyUpdateTarget = Value("--update-target");

        return new AgentArgs(
            service,
            install,
            uninstall,
            unregisterDevice,
            startService,
            stopService,
            acceptEula,
            setup,
            register,
            heartbeatOnce,
            exportTailscaleUp,
            selfTest,
            selfTestJson,
            selfTestOutFile,
            casdoorTokenFile,
            applyUpdatePlan,
            applyUpdateTarget);
    }
}
