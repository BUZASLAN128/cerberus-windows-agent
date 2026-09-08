namespace Cerberus.Agent.Core;

/// <summary>
/// Serializes durable lifecycle intent with the last update authorization check and installer spawn.
/// Lock order is launch fence, then short lifecycle/update journal locks. Never wait for quiescence or MSI while holding it.
/// </summary>
public static class AgentUpdateLaunchFence
{
    /// <summary>Enrollment may serialize approved machine provisioning, but this does not authorize writing lifecycle state.</summary>
    public static Task<FileStream> AcquireForEnrollmentPromotionAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException();
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        if (!identity.IsSystem && !principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Enrollment promotion fence requires elevated authority.");
        return AcquireAsync(ct, AgentUpdateSecurity.DefaultPrivilegedRoot);
    }

    public static async Task<FileStream> AcquireAsync(CancellationToken ct, string? root = null)
    {
        if (root is null && !AgentUpdateSecurity.IsLocalSystem())
            throw new UnauthorizedAccessException("Update launch fence requires SYSTEM authority.");
        root ??= AgentUpdateSecurity.DefaultPrivilegedRoot;
        AgentUpdateSecurity.EnsureProtectedRoot(root);
        var path = Path.Combine(root, "lifecycle-launch.lock");
        AgentUpdateSecurity.ValidateTrustedPath(path, root, allowMissing: true);
        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(25, ct).ConfigureAwait(false);
            }
        }
    }
}
