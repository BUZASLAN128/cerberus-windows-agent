namespace Cerberus.Agent.Core;

public interface ISecretStore
{
    Task SaveAsync(
        AgentIdentity identity,
        string refreshToken,
        string privateKeyPem,
        string backendUrl,
        string? tailscaleLoginServer,
        string? tailscaleAuthkey,
        CancellationToken ct);

    Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)>
        LoadAsync(CancellationToken ct);

    Task ClearAsync(CancellationToken ct);
}

public interface IRequestSigner
{
    string ComputeBodyHash(byte[] bodyBytes);
    string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash);
    string Sign(string canonical);
}

public interface ITokenManager
{
    Task<string> GetAccessTokenAsync(CancellationToken ct);
    Task RefreshAsync(CancellationToken ct);
}

public interface ICommandHandler
{
    string Type { get; }
    Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct);
}

// Status providers are an integration boundary: Core loop consumes opaque snapshots.
public interface IAgentStatusProvider
{
    Task<object?> GetTailscaleAsync(CancellationToken ct);
}

public interface IAgentTelemetryProvider
{
    Task<AgentSnapshotRequest> BuildSnapshotAsync(
        AgentBuildMetadata metadata,
        HeartbeatResponse? lastHeartbeat,
        CancellationToken ct);
}

/// <summary>
/// Optional service-local signal for telemetry that must be refreshed before
/// the normal snapshot cadence. It does not change the snapshot wire contract.
/// </summary>
public interface IAgentTelemetrySnapshotTrigger
{
    /// <summary>
    /// Returns true when provider state differs from the last successfully
    /// submitted snapshot and a fresh snapshot should be attempted.
    /// </summary>
    bool IsSnapshotRefreshRequired();

    /// <summary>
    /// Confirms that the most recently built snapshot was submitted without
    /// an exception, allowing the provider to clear its refresh signal.
    /// </summary>
    void MarkSnapshotSubmitted();
}

public interface IAgentUpdateCoordinator
{
    Task HandleUpdateAsync(HeartbeatResponse response, CancellationToken ct);
}

public sealed record CommandResult(string Status, int? ExitCode, string? Stdout, string? Stderr, object? PostVerify);
