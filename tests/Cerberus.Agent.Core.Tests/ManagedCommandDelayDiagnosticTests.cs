using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class ManagedCommandDelayDiagnosticTests
{
    [Theory]
    [InlineData("windows.local_user.disable")]
    [InlineData("windows.ad_user.disable")]
    public async Task SlowManagedCommandWarnsWhileRunning(string type)
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler(type).Block();
        var dispatcher = new CommandDispatcher(new[] { handler }, new IdempotencyCache(
            Path.Combine(Path.GetDirectoryName(h.StorePath)!, "diagnostic-idem.json"), 20, TimeSpan.FromHours(1)));
        var processor = new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromMinutes(2), 1, h.Log, h.Time);
        var command = new AgentCommand("11111111-1111-4111-8111-111111111111", type, "test-key", new { },
            "33333333-3333-4333-8333-333333333333");
        var processing = processor.ProcessAsync(new[] { command }, default);
        try
        {
            await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            h.Time.Advance(TimeSpan.FromSeconds(59));
            Assert.DoesNotContain(h.Log.Lines, line => line.Contains("pending for at least"));
            h.Time.Advance(TimeSpan.FromSeconds(1));
            await Wait.UntilAsync(() => h.Log.Lines.Any(line => line.Contains("pending for at least")), "managed delay warning");
            Assert.False(processing.IsCompleted);
            handler.Gate.TrySetResult();
            await processing.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.DoesNotContain(h.Log.Lines, line => line.Contains(command.Id) || line.Contains(command.LeaseId!));
            Assert.Single(h.Backend.Results);
        }
        finally { handler.Gate.TrySetResult(); }
    }

    [Fact]
    public async Task UnrelatedCommandNeverProducesManagedDelayWarning()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("agent.health.snapshot").Block();
        var dispatcher = new CommandDispatcher(new[] { handler }, new IdempotencyCache(
            Path.Combine(Path.GetDirectoryName(h.StorePath)!, "diagnostic-idem.json"), 20, TimeSpan.FromHours(1)));
        var processor = new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromMinutes(2), 1, h.Log, h.Time);
        var processing = processor.ProcessAsync(new[] { new AgentCommand("id", handler.Type, "key", new { }) }, default);
        try
        {
            await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            h.Time.Advance(TimeSpan.FromMinutes(2));
            handler.Gate.TrySetResult();
            await processing.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.DoesNotContain(h.Log.Lines, line => line.Contains("Managed account command"));
        }
        finally { handler.Gate.TrySetResult(); }
    }

    [Fact]
    public async Task DiagnosticIsOffWhenLoggerIsNotConfigured()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("windows.local_user.disable").Block();
        var dispatcher = new CommandDispatcher(new[] { handler }, new IdempotencyCache(
            Path.Combine(Path.GetDirectoryName(h.StorePath)!, "diagnostic-idem.json"), 20, TimeSpan.FromHours(1)));
        var processor = new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromMinutes(2), 1, time: h.Time);
        var processing = processor.ProcessAsync(new[] { new AgentCommand("id", handler.Type, "key", new { }) }, default);
        try
        {
            await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            h.Time.Advance(TimeSpan.FromMinutes(2));
            handler.Gate.TrySetResult();
            await processing.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.DoesNotContain(h.Log.Lines, line => line.Contains("Managed account command"));
        }
        finally { handler.Gate.TrySetResult(); }
    }

    [Fact]
    public async Task CompletedManagedCommandCancelsPendingWarning()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("windows.local_user.disable");
        var dispatcher = new CommandDispatcher(new[] { handler }, new IdempotencyCache(
            Path.Combine(Path.GetDirectoryName(h.StorePath)!, "diagnostic-idem.json"), 20, TimeSpan.FromHours(1)));
        var processor = new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromMinutes(2), 1, h.Log, h.Time);
        await processor.ProcessAsync(new[] { new AgentCommand("id", handler.Type, "key", new { }) }, default);
        h.Time.Advance(TimeSpan.FromMinutes(2));
        Assert.DoesNotContain(h.Log.Lines, line => line.Contains("Managed account command"));
    }

    [Fact]
    public async Task BlockedDiagnosticLoggerDoesNotBlockCommandCompletion()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("windows.local_user.disable").Block();
        var dispatcher = new CommandDispatcher(new[] { handler }, new IdempotencyCache(
            Path.Combine(Path.GetDirectoryName(h.StorePath)!, "diagnostic-idem.json"), 20, TimeSpan.FromHours(1)));
        using var logger = new BlockingLogger();
        var processor = new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromMinutes(2), 1, logger, h.Time);
        var processing = processor.ProcessAsync(new[] { new AgentCommand("id", handler.Type, "key", new { }) }, default);
        Task? advance = null;
        try
        {
            await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            advance = Task.Run(() => h.Time.Advance(TimeSpan.FromSeconds(60)));
            await logger.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            handler.Gate.TrySetResult();
            await processing.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Single(h.Backend.Results);
        }
        finally
        {
            handler.Gate.TrySetResult();
            logger.Release.Set();
            if (advance is not null) await advance.WaitAsync(TimeSpan.FromSeconds(10));
            if (logger.Started.Task.IsCompleted) await logger.Finished.Task.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private sealed class BlockingLogger : IAgentLogger, IDisposable
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Finished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public ManualResetEventSlim Release { get; } = new(false);
        public void Info(string message) { }
        public void Warn(string message) { Started.TrySetResult(); Release.Wait(); Finished.TrySetResult(); }
        public void Error(string message, Exception? ex = null) { }
        public void Dispose() => Release.Dispose();
    }
}
