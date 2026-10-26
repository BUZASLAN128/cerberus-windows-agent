using System.Reflection;
using System.Text.Json;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support evidence: RDP listener ownership rule, certificate subject simple name and the failed-logon collection guards.</summary>
[Collection("FailedLogonCursor")]
public sealed class FailedLogonSocFixesTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RdpListening_PortOnlyWhenOwnersAreUnreadable()
    {
        Assert.True(FailedLogonProtocolProbe.RdpListening(new HashSet<int> { 3389 }, 3389, null));
        Assert.False(FailedLogonProtocolProbe.RdpListening(new HashSet<int> { 22 }, 3389, null));
    }

    [Fact]
    public void RdpListening_WithOwners_RequiresSvchostOrUnreadableNameOnThePort()
    {
        var tcp = new HashSet<int> { 3389 };
        Assert.True(FailedLogonProtocolProbe.RdpListening(tcp, 3389, new[] { (3389, (string?)"SvcHost") }));
        Assert.False(FailedLogonProtocolProbe.RdpListening(tcp, 3389, new[] { (3389, (string?)"nginx") }));
        Assert.True(FailedLogonProtocolProbe.RdpListening(tcp, 3389, new[] { (3389, (string?)null) }));
        Assert.False(FailedLogonProtocolProbe.RdpListening(tcp, 3389, new[] { (443, (string?)"svchost") }));
        Assert.False(FailedLogonProtocolProbe.RdpListening(tcp, 3389, Array.Empty<(int, string?)>()));
    }

    [Theory]
    [InlineData("CN=Contoso Signer, O=Contoso Ltd, OU=Dev", "Contoso Signer")]
    [InlineData("O=Contoso Ltd, OU=Dev", "Contoso Ltd")]
    [InlineData("OU=Dev, C=US", "Dev")]
    [InlineData("CN=\"A, B\", O=Org", "A, B")]
    [InlineData("OU=a+CN=b, O=Org", "Org")]
    [InlineData("C=US, L=Oslo", null)]
    [InlineData("not a distinguished name", null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData(null, null)]
    public void SimpleNameFromSubject_IsCnThenOThenOu_AndNeverTheWholeDn(string? subject, string? expected)
        => Assert.Equal(expected, ProcessesTelemetrySectionCollector.SimpleNameFromSubject(subject));

    private static FailedLogonCursorStore Seed(out string dir)
    {
        dir = Path.Combine(Path.GetTempPath(), "fl-gen-" + Guid.NewGuid().ToString("N"));
        var store = new FailedLogonCursorStore(Path.Combine(dir, "c.json"));
        Assert.True(store.Save(new FailedLogonCursorState { LastWindowEndUtc = T0 }));
        return store;
    }

    private static T Field<T>(string name)
        => (T)typeof(FailedLogonSection).GetField(name, BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;

    [Fact]
    public async Task CollectionStillRunningWhenKeepPendingRuns_StagesNoPending()
    {
        // Not a deterministic interleaving: FailedLogonSection reads the real event logs and has no reader seam.
        // The test waits until the committing collection has taken its generation, then runs KeepPendingIfReported
        // while that collection is (normally) still reading. Either order leaves the cursor untouched; the
        // in-flight order is the one that needs the generation guard.
        var store = Seed(out var dir);
        try
        {
            var before = Field<long>("_generation");
            var run = Task.Run(() => FailedLogonSection.CollectAll(store, T0.AddMinutes(5), commit: true, CancellationToken.None));
            var spin = SpinWait.SpinUntil(() => Field<long>("_generation") != before, TimeSpan.FromSeconds(30));
            Assert.True(spin);
            FailedLogonSection.KeepPendingIfReported(null);
            await run.WaitAsync(TimeSpan.FromSeconds(60));
            FailedLogonSection.CommitPending();
            Assert.Equal(T0, store.Load(out _).LastWindowEndUtc);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task SecondCollection_WhileTheGuardIsHeld_ReturnsUnavailableWithoutBlocking()
    {
        var store = Seed(out var dir);
        var guard = Field<object>("CollectGuard");
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var holder = Task.Run(() =>
        {
            lock (guard)
            {
                held.Set();
                release.Wait(TimeSpan.FromSeconds(60));
            }
        });
        try
        {
            Assert.True(held.Wait(TimeSpan.FromSeconds(10)));
            var second = Task.Run(() => FailedLogonSection.CollectAll(store, T0.AddMinutes(5), commit: true, CancellationToken.None));
            var result = await second.WaitAsync(TimeSpan.FromSeconds(10));
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(result.FailedLogons));
            Assert.Equal("unavailable", json.RootElement.GetProperty("status").GetString());
            FailedLogonSection.CommitPending();
            Assert.Equal(T0, store.Load(out _).LastWindowEndUtc);
        }
        finally
        {
            release.Set();
            await holder;
            Directory.Delete(dir, true);
        }
    }
}
