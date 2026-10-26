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
    public void RdpListening_WithOwners_RequiresSvchostOrUnreadableNameWhenRowsExistForThePort()
    {
        var tcp = new HashSet<int> { 3389 };
        Assert.True(FailedLogonProtocolProbe.RdpListening(tcp, 3389, new[] { (3389, (string?)"SvcHost") }));
        Assert.False(FailedLogonProtocolProbe.RdpListening(tcp, 3389, new[] { (3389, (string?)"nginx") }));
        Assert.True(FailedLogonProtocolProbe.RdpListening(tcp, 3389, new[] { (3389, (string?)null) }));
        Assert.True(FailedLogonProtocolProbe.RdpListening(tcp, 3389, new[] { (3389, (string?)"nginx"), (3389, (string?)"svchost") }));
    }

    [Fact]
    public void RdpListening_WithoutAnOwnerRowForThePort_FallsBackToThePortCheck()
    {
        var tcp = new HashSet<int> { 3389 };
        Assert.True(FailedLogonProtocolProbe.RdpListening(tcp, 3389, Array.Empty<(int, string?)>()));
        Assert.True(FailedLogonProtocolProbe.RdpListening(tcp, 3389, new[] { (443, (string?)"nginx") }));
        Assert.False(FailedLogonProtocolProbe.RdpListening(new HashSet<int>(), 3389, Array.Empty<(int, string?)>()));
        Assert.False(FailedLogonProtocolProbe.RdpListening(new HashSet<int>(), 3389, new[] { (443, (string?)"svchost") }));
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

    private static SemaphoreSlim Guard()
        => (SemaphoreSlim)typeof(FailedLogonSection).GetField("CollectGuard", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;

    private static string Window(SecurityLogResult r, string property)
    {
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(r.FailedLogons));
        return json.RootElement.GetProperty(property).GetString()!;
    }

    // The unavailable stand-in has start == end == now; a real collection starts at the stored cursor (T0).
    private static readonly string StartOfRealWindow = FailedLogonSection.Iso(T0);

    [Fact]
    public async Task SecondCollection_WaitsForTheGuard_AndRunsOnceItIsReleased()
    {
        var store = Seed(out var dir);
        var guard = Guard();
        await guard.WaitAsync();
        var held = true;
        try
        {
            var second = Task.Run(() => FailedLogonSection.CollectAll(store, T0.AddMinutes(5), commit: false, CancellationToken.None));
            await Task.Delay(TimeSpan.FromSeconds(1));
            Assert.False(second.IsCompleted);
            guard.Release();
            held = false;
            var result = await second.WaitAsync(TimeSpan.FromSeconds(30));
            Assert.Equal(StartOfRealWindow, Window(result, "window_start_utc"));
        }
        finally
        {
            if (held)
                guard.Release();
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task SecondCollection_HeldPastTheWait_ReturnsUnavailableWithinTheBound()
    {
        var store = Seed(out var dir);
        var guard = Guard();
        await guard.WaitAsync();
        try
        {
            var started = DateTime.UtcNow;
            var result = await Task.Run(() => FailedLogonSection.CollectAll(store, T0.AddMinutes(5), commit: false, CancellationToken.None))
                .WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(5));
            Assert.Equal(FailedLogonSection.Iso(T0.AddMinutes(5)), Window(result, "window_start_utc"));
            Assert.Equal("unavailable", Window(result, "status"));
        }
        finally
        {
            guard.Release();
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task KeepPendingAndCommit_DoNotWaitForTheCollectionGuard()
    {
        var guard = Guard();
        await guard.WaitAsync();
        try
        {
            await Task.Run(() =>
            {
                FailedLogonSection.KeepPendingIfReported(null);
                FailedLogonSection.CommitPending();
            }).WaitAsync(TimeSpan.FromSeconds(1));
        }
        finally
        {
            guard.Release();
        }
    }

    [Fact]
    public void TryStage_RefusesASupersededGeneration_AndAcceptsTheCurrentOne()
    {
        var store = Seed(out var dir);
        FailedLogonSection.KeepPendingIfReported(null);
        try
        {
            var state = new FailedLogonCursorState { LastWindowEndUtc = T0.AddMinutes(5) };
            var report = new object();

            var old = FailedLogonSection.Generation;
            FailedLogonSection.KeepPendingIfReported(null);
            Assert.NotEqual(old, FailedLogonSection.Generation);
            Assert.False(FailedLogonSection.TryStage(old, store, state, report));
            Assert.False(FailedLogonSection.HasPending);

            Assert.True(FailedLogonSection.TryStage(FailedLogonSection.Generation, store, state, report));
            Assert.True(FailedLogonSection.HasPending);
            FailedLogonSection.KeepPendingIfReported(new Dictionary<string, object?> { ["failed_logons"] = new object() });
            Assert.False(FailedLogonSection.HasPending);
            FailedLogonSection.CommitPending();
            Assert.Equal(T0, store.Load(out _).LastWindowEndUtc);
        }
        finally
        {
            FailedLogonSection.KeepPendingIfReported(null);
            Directory.Delete(dir, true);
        }
    }
}
