namespace Cerberus.Agent.App.Actions;

internal enum ServiceControlCommand
{
    Install,
    Uninstall,
    UnregisterDevice,
    Start,
    Stop,
}

internal sealed record ServiceControlResult(bool Succeeded, string Message);

internal static class ServiceControlAction
{
    public static ServiceControlResult Run(ServiceControlCommand command)
    {
        if (!Elevation.IsAdministrator())
            return TryRunElevated(command);

        try
        {
            Execute(command);
            return new ServiceControlResult(Succeeded: true, SuccessMessage(command));
        }
        catch (Exception ex)
        {
            return new ServiceControlResult(Succeeded: false, $"{DisplayName(command)} failed: {ex.Message}");
        }
    }

    private static ServiceControlResult TryRunElevated(ServiceControlCommand command)
    {
        var args = command switch
        {
            ServiceControlCommand.Install => "--install-service",
            ServiceControlCommand.Uninstall => "--uninstall-service",
            ServiceControlCommand.UnregisterDevice => "--unregister-device",
            ServiceControlCommand.Start => "--start-service",
            ServiceControlCommand.Stop => "--stop-service",
            _ => throw new ArgumentOutOfRangeException(nameof(command), command, null),
        };

        return Elevation.TryRunElevated(args)
            ? new ServiceControlResult(Succeeded: true, $"UAC prompt opened to {DisplayName(command).ToLowerInvariant()} service.")
            : new ServiceControlResult(Succeeded: false, $"Could not request elevation to {DisplayName(command).ToLowerInvariant()} service.");
    }

    private static void Execute(ServiceControlCommand command)
    {
        switch (command)
        {
            case ServiceControlCommand.Install:
                AgentServiceProvisioning.InstallOrThrow();
                break;
            case ServiceControlCommand.Uninstall:
                AgentServiceProvisioning.UninstallOrThrow();
                break;
            case ServiceControlCommand.UnregisterDevice:
                AgentServiceProvisioning.UnregisterDeviceOrThrow();
                break;
            case ServiceControlCommand.Start:
                ServiceInstaller.StartOrThrow();
                break;
            case ServiceControlCommand.Stop:
                ServiceInstaller.StopOrThrow();
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(command), command, null);
        }
    }

    private static string DisplayName(ServiceControlCommand command) => command.ToString().ToLowerInvariant();

    private static string SuccessMessage(ServiceControlCommand command) => command switch
    {
        ServiceControlCommand.Install => "Service installed and started.",
        ServiceControlCommand.Uninstall => "Service uninstalled. Device registration preserved.",
        ServiceControlCommand.UnregisterDevice => "Device registration removed.",
        ServiceControlCommand.Start => "Service started.",
        ServiceControlCommand.Stop => "Service stopped.",
        _ => throw new ArgumentOutOfRangeException(nameof(command), command, null),
    };
}
