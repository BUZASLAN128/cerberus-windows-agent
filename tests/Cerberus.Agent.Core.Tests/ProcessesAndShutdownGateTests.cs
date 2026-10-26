using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Support evidence: the local-fixed-disk predicate that gates signer lookups (the gate sits in the private
/// signer reader, which <c>Build</c> does not reach, so only the predicate is asserted) and the shutdown read gate.
/// </summary>
[Collection("FailedLogonCursor")]
public sealed class ProcessesAndShutdownGateTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ShortWait = TimeSpan.FromMilliseconds(50);
    private static readonly DateTimeOffset Now = new(2026, 3, 8, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Boot = Now.AddDays(-2);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(@"\\host\share\x.exe")]
    [InlineData(@"\\?\UNC\host\share\x.exe")]
    [InlineData(@"\\?\C:\x.exe")]
    [InlineData(@"\\.\C:\x.exe")]
    [InlineData("//host/share/x.exe")]
    [InlineData("x.exe")]
    [InlineData("C:x.exe")]
    public void IsLocalFixedPath_RejectsUncDeviceRelativeAndEmptyPaths(string? path)
        => Assert.False(ProcessesTelemetrySectionCollector.IsLocalFixedPath(path, _ => DriveType.Fixed));

    [Fact]
    public void IsLocalFixedPath_DependsOnDriveType()
    {
        string? asked = null;
        Func<string, FileAttributes> plain = _ => FileAttributes.Normal;
        Assert.True(ProcessesTelemetrySectionCollector.IsLocalFixedPath(@"C:\Windows\x.exe", r => { asked = r; return DriveType.Fixed; }, plain));
        Assert.Equal(@"C:\", asked);
        Assert.False(ProcessesTelemetrySectionCollector.IsLocalFixedPath(@"C:\Windows\x.exe", _ => DriveType.Network, plain));
        Assert.False(ProcessesTelemetrySectionCollector.IsLocalFixedPath(@"C:\Windows\x.exe", _ => DriveType.Removable, plain));
        Assert.False(ProcessesTelemetrySectionCollector.IsLocalFixedPath(@"C:\Windows\x.exe", _ => throw new DriveNotFoundException("gone"), plain));
    }

    private static string Norm(string p) => p.Replace('/', '\\').TrimEnd('\\');

    private static (bool Result, List<string> Calls) Probe(string path, Func<string, FileAttributes> attrs)
    {
        var calls = new List<string>();
        var result = ProcessesTelemetrySectionCollector.IsLocalFixedPath(path, _ => DriveType.Fixed, p => { calls.Add(Norm(p)); return attrs(Norm(p)); });
        return (result, calls);
    }

    private static FileAttributes ReparseAt(string p, string reparse)
        => string.Equals(p, reparse, StringComparison.OrdinalIgnoreCase) ? FileAttributes.ReparsePoint | FileAttributes.Directory : FileAttributes.Normal;

    [Fact]
    public void IsLocalFixedPath_RejectsIntermediateReparsePointWithoutQueryingDeeper()
    {
        var (result, calls) = Probe(@"C:\a\link\b\x.exe", p => ReparseAt(p, @"C:\a\link"));
        Assert.False(result);
        Assert.Equal(new[] { @"C:\a", @"C:\a\link" }, calls, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void IsLocalFixedPath_RejectsReparsePointFinalComponent()
    {
        var (result, calls) = Probe(@"C:\a\x.exe", p => ReparseAt(p, @"C:\a\x.exe"));
        Assert.False(result);
        Assert.Equal(new[] { @"C:\a", @"C:\a\x.exe" }, calls, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void IsLocalFixedPath_FailsClosedWhenAttributesCannotBeRead()
        => Assert.False(ProcessesTelemetrySectionCollector.IsLocalFixedPath(
            @"C:\a\x.exe", _ => DriveType.Fixed, _ => throw new FileNotFoundException("gone")));

    [Fact]
    public void IsLocalFixedPath_AcceptsPlainPathAndWalksEveryPrefixTopDown()
    {
        var (result, calls) = Probe(@"C:\a\b\x.exe", p => p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? FileAttributes.Normal : FileAttributes.Directory);
        Assert.True(result);
        Assert.Equal(new[] { @"C:\a", @"C:\a\b", @"C:\a\b\x.exe" }, calls, StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<DateTimeOffset> Events(int count)
        => Enumerable.Range(0, count).Select(i => Now.AddMinutes(-30 * i)).ToList();

    /// <summary>Starts a ReadCached whose fetch blocks until <paramref name="release"/> is set; returns once the fetch holds the gate.</summary>
    private static Task<UnexpectedShutdowns> HoldGate(DateTimeOffset now, ManualResetEventSlim release)
    {
        using var entered = new ManualResetEventSlim(false);
        var task = Task.Run(() => UnexpectedShutdownsProbe.ReadCached(now, Boot, () =>
        {
            entered.Set();
            if (!release.Wait(Bound))
                throw new TimeoutException("test never released the fetch");
            return Events(2);
        }));
        Assert.True(entered.Wait(Bound), "fetch did not start");
        return task;
    }

    [Fact]
    public void ShutdownGate_WaiterTimesOutWithoutCache_ThenHolderCompletes()
    {
        UnexpectedShutdownsProbe.ResetCache();
        using var release = new ManualResetEventSlim(false);
        try
        {
            var holder = HoldGate(Now, release);

            Assert.Throws<TimeoutException>(() => UnexpectedShutdownsProbe.ReadCached(Now, Boot, () => Events(1), ShortWait));

            release.Set();
            Assert.True(holder.Wait(Bound));
            Assert.Equal(2, holder.Result.Count7d);
        }
        finally
        {
            release.Set();
            UnexpectedShutdownsProbe.ResetCache();
        }
    }

    [Fact]
    public void ShutdownGate_WaiterTimesOutWithCache_ReusesTheCachedList()
    {
        UnexpectedShutdownsProbe.ResetCache();
        using var release = new ManualResetEventSlim(false);
        try
        {
            var first = UnexpectedShutdownsProbe.ReadCached(Now, Boot, () => Events(3));
            Assert.Equal(3, first.Count7d);

            var later = Now.AddHours(2); // past the cache TTL, so the holder refetches
            var holder = HoldGate(later, release);

            var waiter = UnexpectedShutdownsProbe.ReadCached(later, Boot,
                () => throw new InvalidOperationException("waiter must not fetch"), ShortWait);
            Assert.Equal(first.Count7d, waiter.Count7d);

            release.Set();
            Assert.True(holder.Wait(Bound));
        }
        finally
        {
            release.Set();
            UnexpectedShutdownsProbe.ResetCache();
        }
    }
}
