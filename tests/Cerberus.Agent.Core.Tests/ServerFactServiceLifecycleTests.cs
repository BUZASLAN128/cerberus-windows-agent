using System.Reflection;
using System.Runtime.CompilerServices;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class ServerFactSectionsTests
{
    [Fact]
    public async Task ServiceLifecycle_StartsAnEmptyCacheAndFeedsClassificationThenStopsIt()
    {
        var time = new ManualTimeProvider(T0);
        var searcher = new FakeUpdateSearcher(_ => Task.FromResult(new WindowsUpdateScan(1, 1,
            Array.Empty<WindowsUpdateEntry>(), new[] { new WindowsUpdatePending("KB1", "Update", true, "Security Updates") })));
        using var cache = new WindowsUpdateCache(searcher, time);
        Assert.Null(cache.TryGet());
        var lifetime = ServiceMode.StartTelemetryBackgroundWork(NullAgentLogger.Instance, cache);
        try
        {
            Assert.True(await searcher.Started.WaitAsync(Guard));
            await WaitUntil(() => time.ActiveDueTimes().Contains(T0 + WindowsUpdateCache.RefreshAfter));
            var collector = new UpdatesTelemetrySectionCollector(cache, () => false);
            var node = Obj(await collector.CollectAsync(Context(), default));
            Assert.Equal("ok", (string?)node["pending"]!["status"]);
            Assert.Equal("Security Updates", (string?)node["pending"]!["items"]![0]!["classification"]);
            time.Advance(TimeSpan.FromMinutes(49));
            Assert.Equal(1, searcher.Calls);
        }
        finally { lifetime.Dispose(); }
        await WaitUntil(() => !time.ActiveDueTimes().Contains(T0 + WindowsUpdateCache.RefreshAfter));
        time.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(1, searcher.Calls);
    }

    [Fact]
    public void CompiledServiceHost_ActuallyCallsTheSharedCacheLifecycleInThisProfile()
    {
        // Inspect the compiled async host so a CERBERUS_SERVER_PROFILE guard at the callsite fails Desktop.
        // This does not start a privileged service or claim installed-host acceptance.
        var run = typeof(ServiceMode).GetMethod(nameof(ServiceMode.RunAsync))!;
        var state = run.GetCustomAttribute<AsyncStateMachineAttribute>()!.StateMachineType;
        var il = state.GetMethod("MoveNext", BindingFlags.NonPublic | BindingFlags.Instance)!.GetMethodBody()!.GetILAsByteArray()!;
        var token = typeof(ServiceMode).GetMethod("StartTelemetryBackgroundWork", BindingFlags.NonPublic | BindingFlags.Static)!.MetadataToken;
        Assert.Contains(Enumerable.Range(0, il.Length - 4), i => il[i] == 0x28 && BitConverter.ToInt32(il, i + 1) == token);
    }
}
