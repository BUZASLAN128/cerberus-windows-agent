using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Observability;

/// <summary>
/// Cross-process log mutex with an explicit DACL. The name derives from the public log path, so an existing
/// mutex is used only when SYSTEM, Administrators or the current user owns it; anything else gets no lock.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class AgentLogMutex
{
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
        AgentNamedMutex.Open(NameFor(logFilePath), current, out var mutex);
        return mutex;
    }

    internal static bool IsTrustedOwner(SecurityIdentifier? owner, SecurityIdentifier current)
        => AgentNamedMutex.IsTrustedOwner(owner, current);
}
