using Cerberus.Agent.App;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// The cross-process enroll lock: one run at a time stages, discards or sends; a busy lock fails before any request.
public sealed partial class EnrollHeadlessModeTests
{
    private static string LockName() => Path.Combine(Path.GetTempPath(), $"CerberusAgent.Tests.EnrollLock.{Guid.NewGuid():N}.lock");

    private static IDisposable? RealLock(string name, TimeSpan wait)
        => EnrollLock.TryAcquire(wait, out var held, name) == EnrollLockOutcome.Acquired ? held : null;

    [Fact]
    public async Task Lock_is_taken_before_any_write_and_held_until_the_run_ends()
    {
        var inner = new FakeHost();
        var host = new SeamHost(inner) { StaleRemoved = true, LockFactory = _ => new Probe() };

        var (exit, _, _) = await ExecuteSeam(host);

        Assert.Equal(0, exit);
        Assert.Equal(["data_root", "lock", "log", "stale", "http", "unlock"], host.Events);
        Assert.Equal([TimeSpan.Zero], host.LockWaits);
    }

    [Fact]
    public async Task Busy_lock_exits_five_before_the_stale_discard_or_request()
    {
        var inner = new FakeHost();
        var host = new SeamHost(inner) { StaleRemoved = true, LockFactory = _ => null };

        var (exit, stdout, stderr) = await ExecuteSeam(host);

        Assert.Equal(5, exit);
        Assert.Contains("enroll_in_progress", stderr, StringComparison.Ordinal);
        Assert.Equal("", stdout);
        Assert.Equal(["data_root"], host.Events);
        Assert.Equal(1, host.DataRootCalls);
        Assert.Empty(inner.Http.Requests);
        Assert.Equal(0, inner.Store.SaveCount);
        Assert.Equal(0, inner.DiscardCalls);
        Assert.Null(inner.FingerprintFile);
    }

    [Fact]
    public async Task Untrusted_lock_owner_exits_seven_before_anything_is_touched()
    {
        var inner = new FakeHost();
        var host = new SeamHost(inner) { LockFactory = _ => throw new UnauthorizedAccessException() };

        var (exit, _, stderr) = await ExecuteSeam(host);

        Assert.Equal(HeadlessEnrollmentExit.Refused, exit);
        Assert.Contains("enroll_lock_untrusted", stderr, StringComparison.Ordinal);
        Assert.Equal(["data_root"], host.Events);
        Assert.Empty(inner.Http.Requests);
    }

    [Fact]
    public async Task Lock_is_released_when_the_run_fails_after_taking_it()
    {
        var inner = new FakeHost();
        var host = new SeamHost(inner) { ServiceStates = [HeadlessServiceState.Other], LockFactory = _ => new Probe() };

        var (exit, _, _) = await ExecuteSeam(host);

        Assert.Equal(HeadlessEnrollmentExit.Unavailable, exit);
        Assert.Equal(["data_root", "lock", "log", "unlock"], host.Events);
    }

    [Fact]
    public async Task Untrusted_data_root_exits_seven_without_taking_the_lock()
    {
        var host = new SeamHost(new FakeHost()) { DataRootTrusted = false, LockFactory = _ => new Probe() };

        var (exit, _, _) = await ExecuteSeam(host);

        Assert.Equal(HeadlessEnrollmentExit.Refused, exit);
        Assert.Equal(["data_root"], host.Events);
    }

    [Fact]
    public async Task Second_run_against_the_real_lock_exits_five_and_sends_nothing_until_the_first_one_ends()
    {
        var name = LockName();
        var first = new SeamHost(new FakeHost()) { LockFactory = w => RealLock(name, w) };
        var second = new FakeHost();
        var secondHost = new SeamHost(second) { StaleRemoved = true, LockFactory = w => RealLock(name, w) };
        using (var held = RealLock(name, TimeSpan.Zero))
        {
            Assert.NotNull(held);

            var (exit, _, stderr) = await ExecuteSeam(secondHost);

            Assert.Equal(5, exit);
            Assert.Contains("enroll_in_progress", stderr, StringComparison.Ordinal);
            Assert.DoesNotContain("stale", secondHost.Events);
            Assert.Empty(second.Http.Requests);
        }

        Assert.Equal(0, (await ExecuteSeam(first)).Exit);
        // The finished run released the lock, so a new one can take it.
        using var again = RealLock(name, TimeSpan.Zero);
        Assert.NotNull(again);
    }

    [Fact]
    public void Real_lock_is_exclusive_across_threads_and_free_again_after_dispose()
    {
        var name = LockName();

        Assert.Equal(EnrollLockOutcome.Acquired, EnrollLock.TryAcquire(TimeSpan.Zero, out var first, name));
        Assert.Equal(EnrollLockOutcome.Busy, EnrollLock.TryAcquire(TimeSpan.Zero, out var blocked, name));
        Assert.Null(blocked);
        first!.Dispose();

        Assert.Equal(EnrollLockOutcome.Acquired, EnrollLock.TryAcquire(TimeSpan.Zero, out var next, name));
        next!.Dispose();
    }

    private sealed class Probe : IDisposable
    {
        public void Dispose() { }
    }
}
