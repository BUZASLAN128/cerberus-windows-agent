using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentUpdateStateStoreTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReconcileInstallerResult_CannotOverwriteConcurrentNewAttempt(bool bestEffortWriter)
    {
        var root = NewRoot();
        var readStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<AgentUpdateState?>? reconciliation = null;
        try
        {
            var store = NewStore(root);
            var first = await store.WriteTransitionAsync(AgentUpdateStates.InstallerStarted, "0.1.0", CancellationToken.None,
                attemptId: "attempt-a", targetVersion: "0.2.0");
            await store.WriteInstallerResultAsync(AgentUpdateInstallerResult.FromMsiExitCode(0, null, null) with
            {
                AttemptId = "attempt-a", ResultId = "result-a",
            }, CancellationToken.None);
            var resultBytes = await File.ReadAllBytesAsync(store.InstallerResultPath);
            async Task<AgentUpdateInstallerResult?> ReadResult(CancellationToken ct)
            {
                var result = await store.ReadInstallerResultAsync(ct);
                readStarted.SetResult();
                await releaseRead.Task.WaitAsync(ct);
                return result;
            }
            reconciliation = store.ReconcileInstallerResultAsync("0.1.0", CancellationToken.None, null, ReadResult);
            await Task.WhenAny(readStarted.Task, reconciliation).WaitAsync(TimeSpan.FromSeconds(10));
            if (!readStarted.Task.IsCompleted)
                await reconciliation;
            var newerWriter = NewStore(root);
            var cache = new IdempotencyCache(Path.Combine(root, "command-cache.json"), 10, TimeSpan.FromHours(1));
            var handlerCalls = 0;
            ICommandHandler handler = new ReportWriterHandler(async ct =>
            {
                handlerCalls++;
                await newerWriter.WriteTransitionAsync(AgentUpdateStates.Staged, "0.1.0", ct,
                    attemptId: "attempt-b", targetVersion: "0.3.0", installerResultId: "result-b");
            });
            if (AgentBuildProfile.IsServer)
                handler = new AgentUpdateRequestCommandHandler(() => new AgentUpdateCoordinator(null!, NullAgentLogger.Instance),
                    newerWriter, NullAgentLogger.Instance, "0.1.0",
                    requestInstall: (_, id, _, key, _, _) =>
                    {
                        Assert.Equal("report-command", id);
                        Assert.Equal("report-key", key);
                        return Task.FromResult(true);
                    },
                    projectCurrent: async ct =>
                    {
                        handlerCalls++;
                        return await newerWriter.WriteTransitionAsync(AgentUpdateStates.Staged, "0.1.0", ct,
                            attemptId: "attempt-b", targetVersion: "0.3.0", installerResultId: "result-b");
                    },
                    configuredSignal: () => new AgentUpdateSignal(false, true, "https://updates.example.test/manifest.json", "test", "dev"));
            var dispatcher = new CommandDispatcher(new[] { handler }, cache);
            var payload = AgentBuildProfile.IsServer
                ? JsonSerializer.SerializeToElement(new { schema_version = "agent.update.request.v1", mode = "install", not_before_utc = DateTimeOffset.UtcNow.AddMinutes(1).ToString("O") })
                : JsonSerializer.SerializeToElement(new { });
            var command = new AgentCommand("report-command", handler.Type, "report-key", payload);
            async Task ProjectNewAttempt()
            {
                if (bestEffortWriter)
                    await newerWriter.TryWriteTransitionAsync(AgentUpdateStates.Staged, "0.1.0", CancellationToken.None,
                        attemptId: "attempt-b", targetVersion: "0.3.0", installerResultId: "result-b");
                else
                    Assert.Equal("DONE", (await dispatcher.DispatchAsync(command, CancellationToken.None)).Status);
            }
            await ProjectNewAttempt();
            var committed = await newerWriter.ReadAsync("0.1.0", CancellationToken.None);
            var committedBytes = await File.ReadAllBytesAsync(store.StatePath);
            Console.WriteLine(JsonSerializer.Serialize(new { bestEffortWriter, handlerType = handler.GetType().Name,
                cachePresent = cache.TryGet(command.IdempotencyKey, out var observed), cacheStatus = observed?.Status,
                committedAttempt = committed.AttemptId, callerRetries = 0 }));
            releaseRead.SetResult();
            await reconciliation;
            if (!bestEffortWriter)
            {
                Assert.True(cache.TryGet(command.IdempotencyKey, out var cached));
                Assert.Equal("DONE", cached.Status);
                Assert.Equal("DONE", (await dispatcher.DispatchAsync(command, CancellationToken.None)).Status);
                Assert.Equal(1, handlerCalls);
            }
            var persisted = await newerWriter.ReadAsync("0.1.0", CancellationToken.None);
            Assert.Equal("attempt-b", persisted.AttemptId);
            Assert.Equal("0.3.0", persisted.TargetVersion);
            Assert.Equal("result-b", persisted.LastInstallerResultId);
            Assert.Equal(AgentUpdateStates.Staged, persisted.State);
            Assert.True(persisted.ReportSequence > first.ReportSequence);
            Assert.Equal(committed, persisted);
            Assert.Equal(committedBytes, await File.ReadAllBytesAsync(store.StatePath));
            Assert.Equal(resultBytes, await File.ReadAllBytesAsync(store.InstallerResultPath));
        }
        finally
        {
            releaseRead.TrySetResult();
            if (reconciliation is not null)
                await reconciliation;
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private sealed class ReportWriterHandler(Func<CancellationToken, Task> write) : ICommandHandler
    {
        public string Type => "test.update-report";
        public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            await write(ct);
            return new CommandResult("DONE", 0, null, null, null);
        }
    }

}
