using System.Globalization;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

/// <summary>Optional signed request constraint, compared with the validated manifest before any artifact I/O.</summary>
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record AgentUpdateExpectedPlan(
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("release_id")] string ReleaseId,
    [property: JsonPropertyName("artifact_sha256")] string ArtifactSha256)
{
    public bool IsValid() => Bounded(Version, 50) && Bounded(ReleaseId, 128) &&
        ArtifactSha256 is { Length: 64 } && ArtifactSha256.All(Uri.IsHexDigit);

    public static AgentUpdateExpectedPlan FromManifest(AgentUpdateManifest manifest)
        => new(manifest.Version, ReleaseIdentity(manifest.Channel, manifest.Sequence), manifest.Sha256.ToLowerInvariant());
    public static AgentUpdateExpectedPlan FromPlan(AgentUpdatePlan plan)
        => new(plan.Version, ReleaseIdentity(plan.Channel, plan.Sequence), plan.Sha256.ToLowerInvariant());
    public static string ReleaseIdentity(string channel, long sequence)
        => channel + ":" + sequence.ToString(CultureInfo.InvariantCulture);
    public bool Matches(AgentUpdateExpectedPlan actual) => IsValid() && actual.IsValid() &&
        Version == actual.Version && ReleaseId == actual.ReleaseId &&
        string.Equals(ArtifactSha256, actual.ArtifactSha256, StringComparison.OrdinalIgnoreCase);
    internal static bool Bounded(string? value, int maximum)
        => !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && value == value.Trim() && !value.Any(char.IsControl);
}

public sealed class AgentUpdatePlanMismatchException() : InvalidOperationException("Requested update plan does not match the trusted manifest.");

public sealed record AgentUpdateStagingResult(AgentUpdatePlan? Plan, AgentUpdateExpectedPlan? Release, bool IsCurrent);

/// <summary>
/// Pending until bound; a bound request follows the attempt's actual final phase. Expiry removes only pre-launch
/// request authority. Terminal phase/attempt anchors bound the projection overlay without deleting the receipt.
/// </summary>
public sealed record AgentUpdateInstallRequest(DateTimeOffset NotBeforeUtc, long LifecycleGeneration,
    DateTimeOffset ExpiresUtc, int Attempts = 0, string? CommandId = null, string? CampaignId = null,
    string? IdempotencyKey = null, AgentUpdateExpectedPlan? ExpectedPlan = null, string? BoundAttemptId = null,
    AgentUpdateExpectedPlan? VerifiedRelease = null, string? TerminalReason = null, DateTimeOffset? TerminalUtc = null,
    string? TerminalJournalPhase = null, string? TerminalJournalAttemptId = null)
{
    [JsonIgnore] public bool IsPending => BoundAttemptId is null && TerminalReason is null;
    [JsonIgnore] public bool IsCorrelated => CommandId is not null;
    public bool SameIdentity(AgentUpdateInstallRequest other) => LifecycleGeneration == other.LifecycleGeneration &&
        CommandId == other.CommandId && CampaignId == other.CampaignId && IdempotencyKey == other.IdempotencyKey && ExpectedPlan == other.ExpectedPlan;
    public bool IsValid() => LifecycleGeneration >= 0 && Attempts is >= 0 and <= 3 &&
        ((CommandId is null && CampaignId is null && IdempotencyKey is null && ExpectedPlan is null) ||
         (AgentUpdateExpectedPlan.Bounded(CommandId, 128) && AgentUpdateExpectedPlan.Bounded(CampaignId, 128) &&
          AgentUpdateExpectedPlan.Bounded(IdempotencyKey, 255))) &&
        (ExpectedPlan is null || ExpectedPlan.IsValid()) && (VerifiedRelease is null || VerifiedRelease.IsValid()) &&
        (BoundAttemptId is null || AgentUpdateSecurity.IsSafeAttemptId(BoundAttemptId)) &&
        (TerminalJournalPhase is null || TerminalReason is not null && AgentUpdateJournalStore.KnownPhase(TerminalJournalPhase)) &&
        (TerminalJournalAttemptId is null || TerminalJournalPhase is not null && AgentUpdateSecurity.IsSafeAttemptId(TerminalJournalAttemptId)) &&
        ((TerminalReason is null && TerminalUtc is null) || TerminalUtc is not null && TerminalReason is
            "current" or "installed" or "expired" or "lifecycle_changed" or "automatic_updates_disabled" or
            "staging_failed" or "plan_mismatch" or "release_unavailable" or "attempt_failed" or "superseded");
}
