using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateStateStoreTests
{
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
        var heartbeat = reconciled.ToHeartbeatStatus();

        Assert.Equal(AgentUpdateStates.PendingReboot, reconciled.State);
        Assert.True(reconciled.RequiresReboot);
        Assert.Equal(3010, reconciled.MsiExitCode);
        Assert.DoesNotContain("msi_log_path", heartbeat.Keys);
        Assert.DoesNotContain("last_installer_result_id", heartbeat.Keys);
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

    private static AgentUpdateStateStore NewStore(string root)
        => new(
            Path.Combine(root, "update-state.json"),
            Path.Combine(root, "update-result.json"));

    private static string NewRoot()
        => Path.Combine(Path.GetTempPath(), "cerberus-update-state-" + Guid.NewGuid().ToString("N"));
}
