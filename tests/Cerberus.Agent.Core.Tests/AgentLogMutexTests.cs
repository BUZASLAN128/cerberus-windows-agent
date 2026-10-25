using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.Core.Tests;

[SupportedOSPlatform("windows")]
public sealed class AgentLogMutexTests : IDisposable
{
    private static readonly SecurityIdentifier LocalSystem = new("S-1-5-18");
    private static readonly SecurityIdentifier Administrators = new("S-1-5-32-544");
    private static readonly SecurityIdentifier Users = new("S-1-5-32-545");

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
                Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup of the per-test temp directory.
        }
    }

    private static SecurityIdentifier CurrentUser()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User!;
    }

    [Fact]
    public void LoggerCreatedMutex_GrantsNothingToEveryoneAuthenticatedUsersOrUsers()
    {
        var path = Path.Combine(_dir, "agent.log");
        using var logger = new AgentFileLogger(path, alsoConsole: false);

        using var opened = MutexAcl.OpenExisting(AgentLogMutex.NameFor(path), MutexRights.ReadPermissions);
        var rules = opened.GetAccessControl()
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .Cast<MutexAccessRule>()
            .Where(r => r.AccessControlType == AccessControlType.Allow)
            .Select(r => (SecurityIdentifier)r.IdentityReference)
            .ToArray();

        Assert.Equal(
            new[] { LocalSystem.Value, Administrators.Value, CurrentUser().Value }.OrderBy(s => s, StringComparer.Ordinal),
            rules.Select(sid => sid.Value).Distinct().OrderBy(s => s, StringComparer.Ordinal));
    }

    [Fact]
    public void ExistingMutexOwnedByAnotherUser_IsRejectedAndWritesDoNotWait()
    {
        var path = Path.Combine(_dir, "agent.log");
        Directory.CreateDirectory(_dir);
        var name = AgentLogMutex.NameFor(path);
        var user = CurrentUser();
        var stranger = new SecurityIdentifier("S-1-5-21-1-2-3-1001");

        // Held and owned by this user (an elevated token would otherwise default the owner to Administrators).
        var security = new MutexSecurity();
        security.SetOwner(user);
        security.AddAccessRule(new MutexAccessRule(user, MutexRights.FullControl, AccessControlType.Allow));
        using var held = MutexAcl.Create(true, name, out var createdNew, security);
        Assert.True(createdNew);
        Assert.Equal(user, held.GetAccessControl().GetOwner(typeof(SecurityIdentifier)));

        try
        {
            // Positive control: the same mutex is accepted when its owner is the current user.
            using (var accepted = AgentLogMutex.Open(path, user))
                Assert.NotNull(accepted);

            // The owner is not the current user, SYSTEM or Administrators: no mutex, so no wait.
            Assert.Null(AgentLogMutex.Open(path, stranger));
        }
        finally
        {
            held.ReleaseMutex();
        }
    }

    [Fact]
    public void MutexThatDeniesTheCurrentUser_DoesNotMakeWritesWait()
    {
        var path = Path.Combine(_dir, "agent.log");
        Directory.CreateDirectory(_dir);

        var squat = new MutexSecurity();
        squat.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), MutexRights.FullControl, AccessControlType.Deny));
        using var held = MutexAcl.Create(true, AgentLogMutex.NameFor(path), out var createdNew, squat);
        Assert.True(createdNew);

        var sw = Stopwatch.StartNew();
        using (var logger = new AgentFileLogger(path, alsoConsole: false))
        {
            for (var i = 0; i < 5; i++)
                logger.Info($"line {i}");
        }

        // Five locked writes against a held mutex would take 10 s; the bound is loose on purpose.
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1.5), $"writes took {sw.Elapsed}");
        Assert.Equal(5, File.ReadAllLines(path).Length);
    }

    [Fact]
    public void OwnerPolicy_AcceptsSystemAdministratorsAndCurrentUserOnly()
    {
        var current = CurrentUser();
        Assert.True(AgentLogMutex.IsTrustedOwner(LocalSystem, current));
        Assert.True(AgentLogMutex.IsTrustedOwner(Administrators, current));
        Assert.True(AgentLogMutex.IsTrustedOwner(current, current));

        Assert.False(AgentLogMutex.IsTrustedOwner(Users, current));
        Assert.False(AgentLogMutex.IsTrustedOwner(new SecurityIdentifier("S-1-5-21-1-2-3-1001"), current));
        Assert.False(AgentLogMutex.IsTrustedOwner(null, current));
    }
}
