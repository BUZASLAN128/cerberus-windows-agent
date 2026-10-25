using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Cerberus.Agent.Core;

/// <summary>Outcome of <see cref="AgentNamedMutex.Open(string, SecurityIdentifier, out Mutex?)"/>.</summary>
public enum AgentNamedMutexState
{
    /// <summary>The mutex could not be created or opened; no handle is returned.</summary>
    Failed,
    CreatedNew,
    /// <summary>The mutex already existed and is owned by SYSTEM, Administrators or the current user.</summary>
    ExistingTrusted,
    /// <summary>The mutex already existed with another owner; no handle is returned and the name must not count as a running instance.</summary>
    ExistingUntrusted,
}

/// <summary>
/// Creates a named mutex with an explicit DACL (SYSTEM, Administrators, current user). An existing mutex is
/// used only when SYSTEM, Administrators or the current user owns it, so another local user cannot squat the name.
/// </summary>
[SupportedOSPlatform("windows")]
public static class AgentNamedMutex
{
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static AgentNamedMutexState Open(string name, out Mutex? mutex)
    {
        mutex = null;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User is { } current ? Open(name, current, out mutex) : AgentNamedMutexState.Failed;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return AgentNamedMutexState.Failed;
        }
    }

    /// <summary>Same as <see cref="Open(string, out Mutex?)"/> with an explicit current user, so tests can drive the owner check.</summary>
    public static AgentNamedMutexState Open(string name, SecurityIdentifier current, out Mutex? mutex)
    {
        mutex = null;
        Mutex? created = null;
        try
        {
            var security = new MutexSecurity();
            foreach (var sid in new[] { LocalSystem, Administrators, current })
                security.AddAccessRule(new MutexAccessRule(sid, MutexRights.FullControl, AccessControlType.Allow));

            created = MutexAcl.Create(false, name, out var createdNew, security);
            if (createdNew)
            {
                mutex = created;
                return AgentNamedMutexState.CreatedNew;
            }

            var owner = created.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (!IsTrustedOwner(owner, current))
            {
                created.Dispose();
                return AgentNamedMutexState.ExistingUntrusted;
            }

            mutex = created;
            return AgentNamedMutexState.ExistingTrusted;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
        {
            created?.Dispose();
            return AgentNamedMutexState.Failed;
        }
    }

    public static bool IsTrustedOwner(SecurityIdentifier? owner, SecurityIdentifier current)
        => owner is not null && (owner.Equals(LocalSystem) || owner.Equals(Administrators) || owner.Equals(current));
}
