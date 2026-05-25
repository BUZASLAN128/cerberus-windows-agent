using Cerberus.Agent.App;

namespace Cerberus.Agent.Service;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (!Environment.UserInteractive || args.Any(arg => string.Equals(arg, "--service", StringComparison.OrdinalIgnoreCase)))
        {
            WindowsServiceHost.RunAsService();
            return 0;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        await ServiceMode.RunAsync(cts.Token).ConfigureAwait(false);
        return 0;
    }
}
