using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class HeartbeatResponseHandlerTests
{
    [Fact]
    public async Task HandleAsync_DoesNotClearSecrets_WhenRevokedWithoutConfirmation()
    {
        var secrets = new CaptureSecretStore();
        var handler = new HeartbeatResponseHandler(secrets, NullAgentLogger.Instance);

        var action = await handler.HandleAsync(
            Response(revoke: """{"revoked":true,"clear_local_credentials":true}"""),
            CancellationToken.None);

        Assert.Equal(HeartbeatControlAction.Continue, action);
        Assert.False(secrets.Cleared);
    }

    [Fact]
    public async Task HandleAsync_ClearsSecrets_WhenRevokedWithExplicitConfirmation()
    {
        var secrets = new CaptureSecretStore();
        var handler = new HeartbeatResponseHandler(secrets, NullAgentLogger.Instance);

        var action = await handler.HandleAsync(
            Response(
                revoke:
                """{"revoked":true,"clear_local_credentials":true,"clear_local_credentials_confirmation":"cerberus-agent-clear-local-credentials-v1"}"""),
            CancellationToken.None);

        Assert.Equal(HeartbeatControlAction.Stop, action);
        Assert.True(secrets.Cleared);
    }

    [Fact]
    public async Task HandleAsync_SkipsCommands_WhenQuarantined()
    {
        var secrets = new CaptureSecretStore();
        var handler = new HeartbeatResponseHandler(secrets, NullAgentLogger.Instance);

        var action = await handler.HandleAsync(
            Response(quarantine: """{"active":true}"""),
            CancellationToken.None);

        Assert.Equal(HeartbeatControlAction.SkipCommands, action);
        Assert.False(secrets.Cleared);
    }

    [Fact]
    public async Task HandleAsync_StagesUpdate_WhenUpgradeRequired()
    {
        var updates = new CaptureUpdateCoordinator();
        var handler = new HeartbeatResponseHandler(
            new CaptureSecretStore(),
            NullAgentLogger.Instance,
            updates);

        var action = await handler.HandleAsync(
            Response(
                update: """{"required":true,"manifest_url":"https://releases.example/manifest.json"}""",
                lifecycle: "upgrading",
                agentStatus: "upgrade_required"),
            CancellationToken.None);

        Assert.Equal(HeartbeatControlAction.SkipCommands, action);
        Assert.True(updates.Called);
    }

    [Fact]
    public async Task HandleAsync_ReportsUpdateFailure_WhenCoordinatorThrows()
    {
        var updates = new ThrowingUpdateCoordinator();
        var reported = false;
        var handler = new HeartbeatResponseHandler(
            new CaptureSecretStore(),
            NullAgentLogger.Instance,
            updates,
            updateFailureReporter: (_, ex, _) =>
            {
                reported = ex is InvalidOperationException;
                return Task.CompletedTask;
            });

        var action = await handler.HandleAsync(
            Response(
                update: """{"required":true,"manifest_url":"https://releases.example/manifest.json"}""",
                lifecycle: "upgrading",
                agentStatus: "upgrade_required"),
            CancellationToken.None);

        Assert.Equal(HeartbeatControlAction.SkipCommands, action);
        Assert.True(reported);
    }

    private static HeartbeatResponse Response(
        string? revoke = null,
        string? quarantine = null,
        string? update = null,
        string? lifecycle = null,
        string? agentStatus = null)
        => new(
            PendingCommands: Array.Empty<AgentCommand>(),
            NextPollSeconds: 60,
            ServerTime: 1,
            ServerTimeUtc: "2026-05-07T00:00:00Z",
            CommandBatchSize: 0,
            NextSnapshotSeconds: 300,
            ConfigVersion: "agent-config.v1",
            LifecycleState: lifecycle ?? (quarantine is null ? "connected" : "quarantined"),
            RegistrationState: "claimed",
            ClaimRequired: false,
            ManifestVersion: null,
            ManagedAccountManifestHash: null,
            ManifestFreshUntil: null,
            RequireManifestBeforeUnlock: false,
            AgentStatus: agentStatus ?? (quarantine is null ? "active" : "quarantined"),
            VersionPolicy: null,
            Update: Parse(update),
            Revoke: Parse(revoke),
            Quarantine: Parse(quarantine));

    private static IReadOnlyDictionary<string, JsonElement>? Parse(string? json)
    {
        if (json is null)
            return null;
        return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
    }

    private sealed class CaptureSecretStore : ISecretStore
    {
        public bool Cleared { get; private set; }

        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct)
        {
            throw new NotSupportedException();
        }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            throw new NotSupportedException();
        }

        public Task ClearAsync(CancellationToken ct)
        {
            Cleared = true;
            return Task.CompletedTask;
        }
    }

    private sealed class CaptureUpdateCoordinator : IAgentUpdateCoordinator
    {
        public bool Called { get; private set; }

        public Task HandleUpdateAsync(HeartbeatResponse response, CancellationToken ct)
        {
            Called = true;
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingUpdateCoordinator : IAgentUpdateCoordinator
    {
        public Task HandleUpdateAsync(HeartbeatResponse response, CancellationToken ct)
            => throw new InvalidOperationException("manifest failed");
    }
}
