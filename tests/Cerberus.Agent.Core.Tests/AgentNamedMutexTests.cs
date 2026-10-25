using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

[SupportedOSPlatform("windows")]
public sealed class AgentNamedMutexTests
{
    private static readonly SecurityIdentifier LocalSystem = new("S-1-5-18");
    private static readonly SecurityIdentifier Administrators = new("S-1-5-32-544");

    private static string NewName() => $@"Local\CerberusAgent.Tests.Named.{Guid.NewGuid():N}";

    private static SecurityIdentifier CurrentUser()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User!;
    }

    [Fact]
    public void Open_CreatesMutexGrantingOnlySystemAdministratorsAndCurrentUser()
    {
        var name = NewName();

        Assert.Equal(AgentNamedMutexState.CreatedNew, AgentNamedMutex.Open(name, out var mutex));
        using (mutex)
        {
            var sids = mutex!.GetAccessControl()
                .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
                .Cast<MutexAccessRule>()
                .Where(r => r.AccessControlType == AccessControlType.Allow)
                .Select(r => ((SecurityIdentifier)r.IdentityReference).Value)
                .Distinct()
                .OrderBy(s => s, StringComparer.Ordinal);

            Assert.Equal(
                new[] { LocalSystem.Value, Administrators.Value, CurrentUser().Value }.OrderBy(s => s, StringComparer.Ordinal),
                sids);
        }
    }

    [Fact]
    public void Open_ExistingMutexOwnedByCurrentUser_IsTrustedAndUntrustedForAnotherUser()
    {
        var name = NewName();
        var user = CurrentUser();
        var stranger = new SecurityIdentifier("S-1-5-21-1-2-3-1001");
        var security = new MutexSecurity();
        security.SetOwner(user);
        security.AddAccessRule(new MutexAccessRule(user, MutexRights.FullControl, AccessControlType.Allow));
        using var held = MutexAcl.Create(false, name, out var createdNew, security);
        Assert.True(createdNew);

        // Positive control: the same mutex is accepted for its owner.
        Assert.Equal(AgentNamedMutexState.ExistingTrusted, AgentNamedMutex.Open(name, user, out var trusted));
        using (trusted)
            Assert.NotNull(trusted);

        // An owner that is not the caller, SYSTEM or Administrators must not count as a running instance.
        Assert.Equal(AgentNamedMutexState.ExistingUntrusted, AgentNamedMutex.Open(name, stranger, out var untrusted));
        Assert.Null(untrusted);
    }

    [Fact]
    public void Open_MutexThatDeniesTheCurrentUser_FailsWithoutHandle()
    {
        var name = NewName();
        var squat = new MutexSecurity();
        squat.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), MutexRights.FullControl, AccessControlType.Deny));
        using var held = MutexAcl.Create(false, name, out var createdNew, squat);
        Assert.True(createdNew);

        Assert.Equal(AgentNamedMutexState.Failed, AgentNamedMutex.Open(name, out var mutex));
        Assert.Null(mutex);
    }
}
