using System.DirectoryServices.ActiveDirectory;

namespace Cerberus.Agent.Integrations.Ad;

public static class AdStatusProbe
{
    public static (bool DomainJoined, string? DomainName, string? Error) Probe()
    {
        try
        {
            var domain = Domain.GetComputerDomain();
            return (true, domain?.Name, null);
        }
        catch (ActiveDirectoryObjectNotFoundException)
        {
            return (false, null, null);
        }
        catch (Exception ex)
        {
            // Best-effort; do not treat as fatal for agent loop.
            return (false, null, $"{ex.GetType().Name}: {ex.Message}");
        }
    }
}

