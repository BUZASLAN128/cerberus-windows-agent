using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Telemetry;

internal sealed record WindowsTelemetryContext(
    AgentBuildMetadata Metadata,
    HeartbeatResponse? LastHeartbeat);
