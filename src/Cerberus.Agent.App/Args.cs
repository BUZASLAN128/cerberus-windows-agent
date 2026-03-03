namespace Cerberus.Agent.App;

internal sealed record AgentArgs(
    bool Tray,
    bool Service,
    bool InstallService,
    bool UninstallService,
    bool StartService,
    bool StopService,
    bool Register,
    bool ExportTailscaleUp,
    bool SelfTest,
    bool SelfTestJson,
    string? SelfTestOutFile,
    string? CasdoorTokenFile);

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

        var tray = Has("--tray");
        var service = Has("--service");
        var install = Has("--install-service");
        var uninstall = Has("--uninstall-service");
        var startService = Has("--start-service");
        var stopService = Has("--stop-service");
        var register = Has("--register");
        var exportTailscaleUp = Has("--export-tailscale-up");
        var selfTest = Has("--self-test");
        var selfTestJson = Has("--self-test-json") || Has("--json");
        var selfTestOutFile = Value("--self-test-out");
        var casdoorTokenFile = Value("--casdoor-token-file") ?? Value("--token-file");

        // Default behavior: tray if no mode provided.
        if (!tray && !service && !install && !uninstall && !startService && !stopService && !register && !exportTailscaleUp && !selfTest)
            tray = true;

        return new AgentArgs(
            tray,
            service,
            install,
            uninstall,
            startService,
            stopService,
            register,
            exportTailscaleUp,
            selfTest,
            selfTestJson,
            selfTestOutFile,
            casdoorTokenFile);
    }
}
