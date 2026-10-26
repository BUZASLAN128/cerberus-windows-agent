using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Support evidence for the listener-owner rule used by RDP and SQL and for the unexpected-shutdown cap. The SQL
/// decision and the collector's <c>status</c> are built inline from live probes, so the owner rule is tested
/// through <c>PortOwned</c> and the cap through <c>ReadCached</c>.
/// </summary>
[Collection("FailedLogonCursor")]
public sealed class FailedLogonSocFixesProbeTests
{
    private static readonly DateTimeOffset Now = new(2026, 3, 8, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Boot = Now.AddDays(-2);

    private static bool Sql(bool open, params (int Port, string? Name)[]? owners)
        => FailedLogonProtocolProbe.PortOwned(open ? new HashSet<int> { 1433 } : new HashSet<int>(), 1433, owners, "sqlservr");

    [Fact]
    public void SqlPort_WithOwnerRows_NeedsSqlservrOrAnUnnamedOwner()
    {
        Assert.False(Sql(true, (1433, "nginx")));
        Assert.True(Sql(true, (1433, "sqlservr")));
        Assert.True(Sql(true, (1433, "SQLSERVR")));
        Assert.True(Sql(true, (1433, null)));
        Assert.True(Sql(true, (1433, "nginx"), (1433, "sqlservr")));
    }

    [Fact]
    public void SqlPort_WithoutUsableOwnerRows_FallsBackToThePortCheck()
    {
        Assert.True(Sql(true, null));
        Assert.True(Sql(true, (80, "nginx")));
        Assert.False(Sql(false, null));
        Assert.False(Sql(false, (80, "nginx")));
    }

    private static IReadOnlyList<DateTimeOffset> Events(int count, int firstAgeMinutes = 0)
        => Enumerable.Range(0, count).Select(i => Now.AddMinutes(-firstAgeMinutes - 30 * i)).ToList();

    private static UnexpectedShutdowns Read(IReadOnlyList<DateTimeOffset> times)
    {
        UnexpectedShutdownsProbe.ResetCache();
        try
        {
            return UnexpectedShutdownsProbe.ReadCached(Now, Boot, () => times);
        }
        finally
        {
            UnexpectedShutdownsProbe.ResetCache();
        }
    }

    [Fact]
    public void Shutdowns_OneEventPastTheCap_IsTruncatedAndCountsTheNewest200()
    {
        var times = Events(UnexpectedShutdownsProbe.MaxEventsRead + 1);
        var read = Read(times);
        Assert.True(read.Truncated);
        Assert.Equal(UnexpectedShutdownsProbe.MaxEventsRead, read.Count7d);
        Assert.Equal(times[0], read.LastUtc);
    }

    [Fact]
    public void Shutdowns_ExactlyTheCap_IsNotTruncated()
    {
        var read = Read(Events(UnexpectedShutdownsProbe.MaxEventsRead));
        Assert.False(read.Truncated);
        Assert.Equal(UnexpectedShutdownsProbe.MaxEventsRead, read.Count7d);
    }

    [Fact]
    public void Shutdowns_ExtraEventOutsideTheSevenDayWindow_IsNotTruncated()
    {
        var times = Events(UnexpectedShutdownsProbe.MaxEventsRead).Append(Now.AddDays(-8)).ToList();
        var read = Read(times);
        Assert.False(read.Truncated);
        Assert.Equal(UnexpectedShutdownsProbe.MaxEventsRead, read.Count7d);
    }

    [Fact]
    public void ShutdownCache_RebootWithinBootToleranceIsDetectedByBootId()
    {
        UnexpectedShutdownsProbe.ResetCache();
        try
        {
            var calls = 0;
            IReadOnlyList<DateTimeOffset> Fetch() { calls++; return Events(1); }

            UnexpectedShutdownsProbe.ReadCached(Now, Boot, Fetch, bootId: 7);
            UnexpectedShutdownsProbe.ReadCached(Now.AddMinutes(5), Boot, Fetch, bootId: 7);
            Assert.Equal(1, calls);
            UnexpectedShutdownsProbe.ReadCached(Now.AddMinutes(6), Boot.AddSeconds(10), Fetch, bootId: 8); // same boot time to the minute
            Assert.Equal(2, calls);
            UnexpectedShutdownsProbe.ReadCached(Now.AddMinutes(7), Boot.AddSeconds(10), Fetch, bootId: null); // id unreadable: boot time decides
            Assert.Equal(2, calls);
        }
        finally
        {
            UnexpectedShutdownsProbe.ResetCache();
        }
    }

    [Fact]
    public void BootId_IsReadOnlyFromADwordValue()
    {
        Assert.Equal(147, UnexpectedShutdownsProbe.BootIdFromValue(147));
        Assert.Null(UnexpectedShutdownsProbe.BootIdFromValue(null));
        Assert.Null(UnexpectedShutdownsProbe.BootIdFromValue("147"));
        Assert.Null(UnexpectedShutdownsProbe.BootIdFromValue(new byte[] { 1 }));
    }
}
