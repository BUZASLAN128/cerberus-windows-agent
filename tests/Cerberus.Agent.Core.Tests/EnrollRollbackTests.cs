#if CERBERUS_SERVER_PROFILE
using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

// Temp folder through the Seams parameter. The service stop in EnrollRollbackMode needs LocalSystem and the real
// service controller and has no seam, so it is not covered here.
public sealed class EnrollRollbackTests : IDisposable
{
    private readonly ServerEnrollmentArtifactsTests _fixture = new();

    public void Dispose() => _fixture.Dispose();

    [Fact]
    public async Task Rollback_removes_pending_store_marker_and_fingerprint_without_the_network()
    {
        _fixture.StageAll();

        var line = await ServerEnrollmentArtifacts.RollbackAsync(default, _fixture.Seams());

        Assert.Equal("Enrollment rollback pending=ok committed=ok fingerprint=ok", line);
        Assert.False(File.Exists(_fixture.Pending));
        Assert.False(File.Exists(_fixture.Marker));
        Assert.False(File.Exists(_fixture.Fingerprint));
        Assert.Equal(["fence", "clear_pending", "validate_marker:adopt.marker", "unfence", "clear_machine"], _fixture.Calls);
    }

    [Fact]
    public async Task Rollback_with_nothing_staged_skips_the_pending_step_and_still_clears_the_rest()
    {
        File.WriteAllText(_fixture.Fingerprint, "x");

        var line = await ServerEnrollmentArtifacts.RollbackAsync(default, _fixture.Seams());

        Assert.Contains("pending=ok", line, StringComparison.Ordinal);
        Assert.False(File.Exists(_fixture.Fingerprint));
        Assert.Equal(["clear_machine"], _fixture.Calls);
    }

    [Fact]
    public async Task Rollback_steps_are_independent_and_a_failure_is_reported_by_type_only()
    {
        _fixture.StageAll();

        var line = await ServerEnrollmentArtifacts.RollbackAsync(default,
            _fixture.Seams(clearPending: () => throw new IOException("secret path"), clearMachine: () => throw new UnauthorizedAccessException("secret")));

        Assert.Equal("Enrollment rollback pending=IOException committed=UnauthorizedAccessException fingerprint=ok", line);
        Assert.False(File.Exists(_fixture.Marker));
        Assert.False(File.Exists(_fixture.Fingerprint));
        Assert.DoesNotContain("secret", line, StringComparison.Ordinal);
    }

    // Run() uses the real host, service controller and LocalSystem check and has no seam, so its order is pinned on source.
    [Fact]
    public void Rollback_gates_the_data_root_before_the_log_the_lock_and_any_deletion()
    {
        var source = ReadAppSource("EnrollRollbackMode.cs");

        var system = Index(source, "IsLocalSystem()");
        var gate = Index(source, "EnsureDataRootProtected()");
        var gateExit = Index(source, "return 1;");
        var log = Index(source, "host.OpenLog()");
        var take = Index(source, "TryAcquireEnrollLock(LockWait)");
        var busyExit = Index(source, "return 0;", take);
        var stop = Index(source, "StopService(log);");
        var delete = Index(source, "ServerEnrollmentArtifacts.RollbackAsync(");

        Assert.True(system < gate && gate < gateExit && gateExit < log && log < take && take < busyExit && busyExit < stop && stop < delete);
        Assert.Equal(1, source.Split("host.OpenLog()").Length - 1);
    }

    [Fact]
    public void Headless_enroll_gates_and_locks_before_opening_the_file_logger()
    {
        var source = ReadAppSource("EnrollHeadlessMode.cs");

        var execute = Index(source, "internal static async Task<int> ExecuteAsync(");
        var preflight = Index(source, "Preflight(rawProof, fromInstaller, host, out var runLock)", execute);
        var log = Index(source, "host.OpenLog()", execute);
        var gate = Index(source, "host.EnsureDataRootProtected()");
        var take = Index(source, "host.TryAcquireEnrollLock(TimeSpan.Zero)");

        Assert.True(preflight < log);
        Assert.True(gate < take);
        Assert.Equal(1, source.Split("host.OpenLog()").Length - 1);
    }

    private static int Index(string source, string needle, int from = 0)
    {
        var at = source.IndexOf(needle, from, StringComparison.Ordinal);
        Assert.True(at >= 0, needle);
        return at;
    }

    private static string ReadAppSource(string file)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Cerberus.WindowsAgent.slnx")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, "src", "Cerberus.Agent.App", file));
    }
}
#endif
