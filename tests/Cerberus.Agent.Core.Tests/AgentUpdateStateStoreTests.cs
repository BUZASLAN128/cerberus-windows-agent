using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateStateStoreTests
{
    [Fact]
    public async Task ReconcileInstallerResult_LeavesNewAttemptUnchangedAcrossRepeatedStaleResults()
    {
        var root = NewRoot();
        try
        {
            var store = NewStore(root);
            var current = await store.WriteTransitionAsync(AgentUpdateStates.Staged, "0.1.0", CancellationToken.None,
                attemptId: "attempt-b", targetVersion: "0.3.0", installerResultId: "committed-result");
            await store.WriteInstallerResultAsync(AgentUpdateInstallerResult.FromMsiExitCode(0, null, null) with
            {
                AttemptId = "attempt-a", ResultId = "uncommitted-result",
            }, CancellationToken.None);
            var stateBytes = await File.ReadAllBytesAsync(store.StatePath);
            var resultBytes = await File.ReadAllBytesAsync(store.InstallerResultPath);
            var log = new RecordingLogger();

            for (var i = 0; i < 2; i++)
                Assert.Equal(current, await NewStore(root).ReconcileInstallerResultAsync("0.1.0", CancellationToken.None, log));

            Assert.Equal(stateBytes, await File.ReadAllBytesAsync(store.StatePath));
            Assert.Equal(resultBytes, await File.ReadAllBytesAsync(store.InstallerResultPath));
            Assert.Equal(2, log.Lines.Count);
            Assert.All(log.Lines, line => Assert.Contains("Installer result ignored: active attempt mismatch. at=AgentUpdateStateStore.ReconcileInstallerResultAsync", line));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

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

    [Fact]
    public async Task MissingDurableStateDoesNotEmitOrderedHeartbeatReportsOrWriteDuringStatusReads()
    {
        var root = NewRoot();
        var store = NewStore(root);
        foreach (var version in new[] { "0.1.0", "0.1.0", "0.2.0" })
        {
            var display = await store.ReadAsync(version, CancellationToken.None);
            Assert.Equal(AgentUpdateStates.NotChecked, display.State);
            Assert.Equal(version, display.CurrentVersion);
            Assert.Null(await store.ReconcileInstallerResultAsync(version, CancellationToken.None));
            Assert.False(Directory.Exists(root));
            store = NewStore(root);
        }
    }

    [Fact]
    public async Task ReportPayloadAndSequenceStayBoundAcrossReadsRestartAndRealVersionTransition()
    {
        var root = NewRoot();
        try
        {
            var store = NewStore(root);
            var first = await store.WriteTransitionAsync(AgentUpdateStates.Current, "0.1.0", CancellationToken.None);
            Assert.True(first.ReportSequence > 0);
            var bytes = await File.ReadAllBytesAsync(store.StatePath);
            var repeated = await NewStore(root).ReconcileInstallerResultAsync("0.2.0", CancellationToken.None);
            Assert.NotNull(repeated);
            Assert.Equal(first.ToHeartbeatStatus(), repeated.ToHeartbeatStatus());
            Assert.Equal(bytes, await File.ReadAllBytesAsync(store.StatePath));

            var changed = await store.WriteTransitionAsync(AgentUpdateStates.Current, "0.2.0", CancellationToken.None);
            Assert.Equal(first.ReportSequence + 1, changed.ReportSequence);
            Assert.Equal("0.2.0", changed.CurrentVersion);
            var report = await NewStore(root).ReconcileInstallerResultAsync("0.2.0", CancellationToken.None);
            Assert.NotNull(report);
            Assert.Equal(changed.ToCommandResultPayload(), report.ToHeartbeatStatus());
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task WriteTransitionAsync_PersistsStagedStateForRestart()
    {
        var root = NewRoot();
        var store = NewStore(root);

        await store.WriteTransitionAsync(
            AgentUpdateStates.Staged,
            currentVersion: "0.1.0",
            CancellationToken.None,
            targetVersion: "0.2.0",
            channel: "dev",
            manifestUrl: "https://releases.example.test/update-manifest.json",
            campaignId: "campaign-1",
            commandId: "command-1",
            artifactSha256: new string('a', 64));

        var reloaded = await NewStore(root).ReadAsync("0.1.0", CancellationToken.None);

        Assert.Equal(AgentUpdateStates.Staged, reloaded.State);
        Assert.Equal("0.2.0", reloaded.TargetVersion);
        Assert.Equal("campaign-1", reloaded.CampaignId);
        Assert.True(File.Exists(Path.Combine(root, "update-state.json")));
    }

    [Fact]
    public async Task ReadAsync_RejectsCorruptJsonWithoutResettingState()
    {
        var root = NewRoot();
        Directory.CreateDirectory(root);
        await File.WriteAllTextAsync(Path.Combine(root, "update-state.json"), "{not-json");

        await Assert.ThrowsAsync<InvalidOperationException>(() => NewStore(root).ReadAsync("0.1.0", CancellationToken.None));
        Assert.Equal("{not-json", await File.ReadAllTextAsync(Path.Combine(root, "update-state.json")));
    }

    [Fact]
    public async Task TryWriteTransitionAsync_ReturnsTransitionWhenStatePathCannotBeWritten()
    {
        var root = NewRoot();
        await File.WriteAllTextAsync(root, "not-a-directory");
        var store = NewStore(root);

        var state = await store.TryWriteTransitionAsync(
            AgentUpdateStates.Current,
            currentVersion: "0.2.0",
            CancellationToken.None,
            targetVersion: "0.2.0",
            channel: "dev",
            manifestUrl: "https://releases.example.test/update-manifest.json",
            markChecked: true);

        Assert.Equal(AgentUpdateStates.Current, state.State);
        Assert.Equal("0.2.0", state.CurrentVersion);
        Assert.False(Directory.Exists(root));
        Assert.True(File.Exists(root));
    }

    [Fact]
    public async Task ReconcileInstallerResult_UpdatesStateWithoutLeakingLogPath()
    {
        var root = NewRoot();
        var store = NewStore(root);
        await store.WriteTransitionAsync(
            AgentUpdateStates.InstallerStarted,
            currentVersion: "0.1.0",
            CancellationToken.None,
            targetVersion: "0.2.0",
            channel: "dev",
            manifestUrl: "https://releases.example.test/update-manifest.json",
            campaignId: "campaign-1");
        await store.WriteInstallerResultAsync(
            AgentUpdateInstallerResult.FromMsiExitCode(
                3010,
                errorMessage: null,
                msiLogPath: @"C:\ProgramData\CerberusAgent\updates\logs\msiexec.log"),
            CancellationToken.None);

        var reconciled = await store.ReconcileInstallerResultAsync("0.2.0", CancellationToken.None);
        Assert.NotNull(reconciled);
        var heartbeat = reconciled.ToHeartbeatStatus();

        Assert.Equal(AgentUpdateStates.PendingReboot, reconciled.State);
        Assert.True(reconciled.RequiresReboot);
        Assert.Equal(3010, reconciled.MsiExitCode);
        Assert.DoesNotContain("msi_log_path", heartbeat.Keys);
        Assert.DoesNotContain("last_installer_result_id", heartbeat.Keys);
        var persisted = await NewStore(root).ReadAsync("0.2.0", CancellationToken.None);
        Assert.Equal(persisted.ReportSequence, reconciled.ReportSequence);
        Assert.Equal(persisted.ToHeartbeatStatus(), heartbeat);
        var repeated = await NewStore(root).ReconcileInstallerResultAsync("0.2.0", CancellationToken.None);
        Assert.NotNull(repeated);
        Assert.Equal(heartbeat, repeated.ToHeartbeatStatus());
    }

    [Fact]
    public async Task CurrentTransition_ClearsPriorFailureAndCommandResultOmitsPrivateFields()
    {
        var root = NewRoot();
        var store = NewStore(root);
        await store.WriteTransitionAsync(
            AgentUpdateStates.Failed,
            currentVersion: "0.1.0",
            CancellationToken.None,
            targetVersion: "0.2.0",
            channel: "dev",
            manifestUrl: "https://releases.example.test/private/update-manifest.json",
            errorCode: AgentUpdateErrorCodes.ManifestUnavailable,
            errorMessage: "network path contained local detail");

        var current = await store.WriteTransitionAsync(
            AgentUpdateStates.Current,
            currentVersion: "0.1.0",
            CancellationToken.None,
            targetVersion: "0.1.0",
            channel: "dev",
            manifestUrl: "https://releases.example.test/private/update-manifest.json",
            markChecked: true);
        var commandResult = current.ToCommandResultPayload();

        Assert.Equal(AgentUpdateStates.Current, current.State);
        Assert.Null(current.LastErrorCode);
        Assert.Null(current.LastErrorMessage);
        Assert.DoesNotContain("manifest_url", commandResult.Keys);
        Assert.DoesNotContain("last_error_message", commandResult.Keys);
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

    private static AgentUpdateStateStore NewStore(string root)
        => new(
            Path.Combine(root, "update-state.json"),
            Path.Combine(root, "update-result.json"));

    private static string NewRoot()
        => Path.Combine(Path.GetTempPath(), "cerberus-update-state-" + Guid.NewGuid().ToString("N"));
}
