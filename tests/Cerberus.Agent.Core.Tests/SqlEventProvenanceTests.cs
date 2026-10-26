using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support evidence: 18456 events count as verified only from the SQL service's own process; one real service lookup.</summary>
public sealed class SqlEventProvenanceTests
{
    private static readonly DateTimeOffset Started = new(2026, 3, 1, 8, 0, 0, TimeSpan.Zero);
    private static readonly IReadOnlyList<string> Fields = new[] { "sa", "Password did not match", "[CLIENT: 203.0.113.9]" };

    private static SqlEventProvenance With(Dictionary<string, (int, DateTimeOffset)> services, List<string>? asked = null)
        => new(name =>
        {
            asked?.Add(name);
            return services.TryGetValue(name, out var s) ? s : null;
        });

    private static readonly Dictionary<string, (int, DateTimeOffset)> Running = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MSSQLSERVER"] = (4100, Started),
        ["MSSQL$PROD"] = (5200, Started),
    };

    [Fact]
    public void MatchingProcessAfterServiceStart_IsVerifiedWithTheClientAddress()
    {
        var e = With(Running).Classify("MSSQLSERVER", 4100, Started.AddMinutes(5), Fields);
        Assert.Equal(FailedLogonSource.Sql18456, e.Source);
        Assert.Equal("203.0.113.9", e.SourceIp);
        Assert.True(With(Running).IsVerified("MSSQLSERVER", 4100, Started));
    }

    [Theory]
    [InlineData(1234)]
    [InlineData(0)]
    [InlineData(null)]
    public void OtherOrMissingProcessId_IsUnverifiedAndCarriesNoAddress(int? pid)
    {
        var e = With(Running).Classify("MSSQLSERVER", pid, Started.AddMinutes(5), Fields);
        Assert.Equal(FailedLogonSource.Sql18456Unverified, e.Source);
        Assert.Null(e.SourceIp);
    }

    [Fact]
    public void EventBeforeTheProcessStarted_IsUnverified()
        => Assert.False(With(Running).IsVerified("MSSQLSERVER", 4100, Started.AddTicks(-1)));

    [Fact]
    public void MissingOrStoppedService_IsUnverified()
        => Assert.False(With(new Dictionary<string, (int, DateTimeOffset)>()).IsVerified("MSSQLSERVER", 4100, Started.AddMinutes(1)));

    [Fact]
    public void NamedInstance_IsLookedUpAsItsOwnService_OncePerProvider()
    {
        var asked = new List<string>();
        var provenance = With(Running, asked);
        Assert.True(provenance.IsVerified("MSSQL$PROD", 5200, Started.AddMinutes(1)));
        Assert.False(provenance.IsVerified("MSSQL$PROD", 4100, Started.AddMinutes(2)));
        Assert.False(provenance.IsVerified("MSSQLSERVER", 5200, Started.AddMinutes(3)));
        Assert.Equal(new[] { "MSSQL$PROD", "MSSQLSERVER" }, asked);
    }

    [Fact]
    public void Tally_CountsUnverifiedSeparately_AndNeverAsAnAddressGroup()
    {
        var provenance = With(Running);
        var tally = FailedLogonClassifier.Tally(new[]
        {
            provenance.Classify("MSSQLSERVER", 4100, Started.AddMinutes(1), Fields),
            provenance.Classify("MSSQLSERVER", 99, Started.AddMinutes(2), Fields),
        });
        Assert.Equal(1, tally.Counts["sql"]);
        Assert.Equal(1, tally.SqlUnverified);
        Assert.Single(tally.Groups);
    }

    [Fact]
    public void LiveLookup_ReadsTheServiceManagerProcessIdOfARealService()
    {
        Assert.True(SqlEventProvenance.ServiceProcessId("EventLog") > 0);
        Assert.Null(SqlEventProvenance.ServiceProcessId("CerberusNoSuchService"));
        Assert.Null(SqlEventProvenance.LookupService("CerberusNoSuchService"));
    }
}
