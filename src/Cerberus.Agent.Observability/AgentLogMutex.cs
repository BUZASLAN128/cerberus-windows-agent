using System.Security.AccessControl;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace Cerberus.Agent.Observability;

/// <summary>
/// Cross-process log mutex with an explicit DACL. The name derives from the public log path, so an existing
/// mutex is used only when SYSTEM, Administrators or the current user owns it; anything else gets no lock.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class AgentLogMutex
{
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    internal static string NameFor(string logFilePath)
    {
        var path = Path.GetFullPath(logFilePath).ToUpperInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path)));
        return $"Global\\Cerberus.AgentLog.{hash[..32]}";
    }

    /// <summary>Null when the mutex cannot be created, opened or trusted; the caller then writes without a lock.</summary>
    internal static Mutex? Open(string logFilePath)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User is { } current ? Open(logFilePath, current) : null;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return null;
        }
    }

    /// <summary>Same as <see cref="Open(string)"/> with an explicit current user, so tests can drive the owner check.</summary>
    internal static Mutex? Open(string logFilePath, SecurityIdentifier current)
    {
        Mutex? mutex = null;
        try
        {
            var security = new MutexSecurity();
            foreach (var sid in new[] { LocalSystem, Administrators, current })
                security.AddAccessRule(new MutexAccessRule(sid, MutexRights.FullControl, AccessControlType.Allow));

            mutex = MutexAcl.Create(false, NameFor(logFilePath), out var createdNew, security);
            if (!createdNew)
            {
                var owner = mutex.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                if (!IsTrustedOwner(owner, current))
                {
                    mutex.Dispose();
                    return null;
                }
            }

            return mutex;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
        {
            mutex?.Dispose();
            return null;
        }
    }

    internal static bool IsTrustedOwner(SecurityIdentifier? owner, SecurityIdentifier current)
        => owner is not null && (owner.Equals(LocalSystem) || owner.Equals(Administrators) || owner.Equals(current));
}
