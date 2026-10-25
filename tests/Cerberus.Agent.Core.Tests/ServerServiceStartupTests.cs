#if CERBERUS_SERVER_PROFILE
using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

// Support tier: delegates replace the service, outbox and replay store. The ServiceMode wiring is checked
// by source order only; the real start-up path needs the live service acceptance.
public sealed class ServerServiceStartupTests
{
    private sealed class RecordingLogger : IAgentLogger
    {
        public List<string> Errors { get; } = new();
        public void Info(string message) { }
        public void Warn(string message) { }
        public void Error(string message, Exception? ex = null) => Errors.Add(message);
    }

    private sealed class Harness
    {
        public bool RevokePending = true;
        public bool ReplayAvailable = true;
        public bool Stopped;
        public Func<Task>? Drain;
        public Func<Task>? Recover;
        public List<string> Calls { get; } = new();
        public RecordingLogger Log { get; } = new();

        public ServerServiceStartup Build() => new(
            () => RevokePending,
            async _ => { Calls.Add("drain"); if (Drain is not null) await Drain(); },
            async _ => { Calls.Add("recover"); if (Recover is not null) await Recover(); },
            () => ReplayAvailable,
            () => Stopped,
            () => { Calls.Add("stop"); Stopped = true; },
            Log);
    }

    [Fact]
    public async Task Recover_DrainsOutboxBeforeRecordingRevoke_AndAllowsNetwork()
    {
        var h = new Harness();

        var allowed = await h.Build().RecoverPendingRevokeAsync(CancellationToken.None, CancellationToken.None);

        Assert.True(allowed);
        Assert.Equal(new[] { "drain", "recover" }, h.Calls);
    }

    [Fact]
    public async Task Recover_WithoutPendingRevoke_SkipsDrainAndAllowsNetwork()
    {
        var h = new Harness { RevokePending = false };

        var allowed = await h.Build().RecoverPendingRevokeAsync(CancellationToken.None, CancellationToken.None);

        Assert.True(allowed);
        Assert.Equal(new[] { "recover" }, h.Calls);
    }

    [Fact]
    public async Task Recover_OutboxFailure_StopsNetworkAndSkipsRecovery()
    {
        var h = new Harness { Drain = () => throw new IOException("outbox") };

        var allowed = await h.Build().RecoverPendingRevokeAsync(CancellationToken.None, CancellationToken.None);

        Assert.False(allowed);
        Assert.Equal(new[] { "drain", "stop" }, h.Calls);
        Assert.Single(h.Log.Errors);
    }

    [Fact]
    public async Task Recover_OutboxCancellation_IsNotSwallowed()
    {
        var h = new Harness { Drain = () => throw new OperationCanceledException() };

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            h.Build().RecoverPendingRevokeAsync(CancellationToken.None, CancellationToken.None));
        Assert.False(h.Stopped);
    }

    [Fact]
    public async Task Recover_RecoveryFailure_PropagatesSoNoHeartbeatStarts()
    {
        var h = new Harness { Recover = () => throw new InvalidOperationException("record failed") };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            h.Build().RecoverPendingRevokeAsync(CancellationToken.None, CancellationToken.None));
    }

    [Fact]
    public async Task Recover_RevokeStillPendingWithUnavailableReplayStore_FailsClosed()
    {
        var h = new Harness { ReplayAvailable = false };

        var allowed = await h.Build().RecoverPendingRevokeAsync(CancellationToken.None, CancellationToken.None);

        Assert.False(allowed);
        Assert.True(h.Stopped);
        Assert.Single(h.Log.Errors);
    }

    [Fact]
    public async Task Recover_RevokeRecordedWithUnavailableReplayStore_AllowsNetwork()
    {
        var h = new Harness { ReplayAvailable = false };
        h.Recover = () => { h.RevokePending = false; return Task.CompletedTask; };

        var allowed = await h.Build().RecoverPendingRevokeAsync(CancellationToken.None, CancellationToken.None);

        Assert.True(allowed);
        Assert.False(h.Stopped);
    }

    [Fact]
    public async Task Recover_NetworkStoppedByRevokeHandler_ReturnsFalse()
    {
        var h = new Harness();
        h.Recover = () => { h.Stopped = true; return Task.CompletedTask; };

        var allowed = await h.Build().RecoverPendingRevokeAsync(CancellationToken.None, CancellationToken.None);

        Assert.False(allowed);
    }

    [Fact]
    public void EnsureDataRoot_UntrustedRoot_Throws_AndTrustedRootPasses()
    {
        ServerServiceStartup.EnsureDataRoot(() => true);

        Assert.Throws<InvalidOperationException>(() => ServerServiceStartup.EnsureDataRoot(() => false));
    }

    [Fact]
    public void ServiceMode_ChecksDataRootBeforeCreatingFileLogger()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Cerberus.WindowsAgent.slnx")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        var source = File.ReadAllText(Path.Combine(dir!.FullName, "src", "Cerberus.Agent.App", "ServiceMode.cs"));

        var gate = source.IndexOf("ServerServiceStartup.EnsureDataRoot(", StringComparison.Ordinal);
        var logger = source.IndexOf("AgentFileLogger.CreateService(", StringComparison.Ordinal);

        Assert.True(gate >= 0 && logger >= 0 && gate < logger);
    }
}
#endif
