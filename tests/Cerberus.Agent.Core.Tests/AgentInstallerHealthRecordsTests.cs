using System.Security.AccessControl;
using System.Security.Principal;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support-tier checks for binding installer health-failure records to one update attempt.</summary>
public sealed class AgentInstallerHealthRecordsTests : IDisposable
{
    private static readonly DateTimeOffset Started = DateTimeOffset.Parse("2026-10-26T10:00:00Z");
    private readonly string root = Path.Combine(Path.GetTempPath(), "cerberus-health-records-" + Guid.NewGuid().ToString("N"));

    // EnsureProtectedRoot creates the root with an SYSTEM/Administrators-owned ACL, which needs an elevated token
    // (same limit as AgentUpdateStagerTests). Unelevated runs of the record-reading tests return early.
    private static bool Elevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem || new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public void Dispose()
    {
        if (Elevated && Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }

    // The root must not pre-exist: NewestPhaseSince rejects a directory that inherited the temp folder's user ACE.
    private void CreateProtectedRoot() => AgentUpdateSecurity.EnsureProtectedRoot(root);

    private void Record(string name, DateTimeOffset at, string phase, string? version = "9.9.9")
        => AgentUpdateDurableFile.Write(Path.Combine(root, name + ".health-failure.json"), root,
            new AgentInstallerHealthDiagnostic("v1", "health", at, phase, "unexpected", "Exception", null, version, null, null, null, null));

    private AgentInstallerHealthPhase? Scan(DateTimeOffset? started = null)
        => AgentInstallerHealthRecords.NewestPhaseSince(root, started ?? Started, "9.9.9", null);

    // Same descriptors the elevated tests rely on, checked without elevation.
    [Theory]
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)", true)] // root, as EnsureProtectedRoot creates it
    [InlineData("O:BAG:SYD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;GRGX;;;BU)", true)]       // record file inheriting it, created by an elevated admin
    [InlineData("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;AU)", false)]  // what a plain temp folder grants: an untrusted writer
    [InlineData("O:BUG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", false)]                  // untrusted owner
    public void ProtectedRootAndRecordDescriptorsAreAcceptedAndTempStyleOnesRejected(string sddl, bool accepted)
    {
        var descriptor = new RawSecurityDescriptor(sddl);
        if (accepted) AgentUpdateSecurity.ValidateDescriptor(descriptor);
        else Assert.Throws<InvalidOperationException>(() => AgentUpdateSecurity.ValidateDescriptor(descriptor));
    }

    [Fact]
    public void RootThatInheritedTheTempUserAclIsNotReadAndYieldsNull()
    {
        Directory.CreateDirectory(root);
        try
        {
            File.WriteAllText(Path.Combine(root, "a.health-failure.json"), "{}");
            Assert.Null(Scan());
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void CurrentAttemptRecordReturnsItsPhase()
    {
        if (!Elevated) return;
        CreateProtectedRoot();
        Record("a", Started, "service_executable_hash");
        Assert.Equal(AgentInstallerHealthPhase.ServiceExecutableHash, Scan());
    }

    [Fact]
    public void NewestOfSeveralCurrentRecordsWins()
    {
        if (!Elevated) return;
        CreateProtectedRoot();
        Record("a", Started.AddMinutes(1), "stability");
        Record("b", Started.AddMinutes(2), "pipe_connect");
        Record("c", Started.AddMinutes(-5), "service_state");
        Assert.Equal(AgentInstallerHealthPhase.PipeConnect, Scan());
    }

    [Fact]
    public void RecordFromBeforeTheInstallerStartedIsIgnored()
    {
        if (!Elevated) return;
        CreateProtectedRoot();
        Record("a", Started.AddSeconds(-1), "stability");
        Assert.Null(Scan());
    }

    [Fact]
    public void WithoutInstallerStartTimeNothingIsBound()
    {
        if (!Elevated) return;
        CreateProtectedRoot();
        Record("a", Started, "stability");
        Assert.Null(AgentInstallerHealthRecords.NewestPhaseSince(root, null, "9.9.9", null));
    }

    [Fact]
    public void RecordForAnotherVersionIsIgnored()
    {
        if (!Elevated) return;
        CreateProtectedRoot();
        Record("a", Started, "stability", version: "1.0.0");
        Record("b", Started, "stability", version: null);
        Assert.Null(Scan());
    }

    [Fact]
    public void UnknownPhaseIsIgnored()
    {
        if (!Elevated) return;
        CreateProtectedRoot();
        Record("a", Started, "not_a_phase");
        Assert.Null(Scan());
    }

    [Fact]
    public void CorruptRecordIsSkippedAndDoesNotHideAValidOne()
    {
        if (!Elevated) return;
        CreateProtectedRoot();
        File.WriteAllText(Path.Combine(root, "bad.health-failure.json"), "{ not json");
        Assert.Null(Scan());
        Record("good", Started, "stability");
        Assert.Equal(AgentInstallerHealthPhase.Stability, Scan());
    }

    [Fact]
    public void MissingDirectoryYieldsNull()
        => Assert.Null(AgentInstallerHealthRecords.NewestPhaseSince(
            Path.Combine(root, "missing", "deeper"), Started, "9.9.9", null));
}
