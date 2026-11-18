using System.IO;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal static class LkgSignedFloor
{
    internal sealed record Candidate(string MinimumVersion, long Sequence, string ManifestDigest);
    internal sealed record Inspection(Candidate? Pending);

    internal static AgentUpdatePlan? ReadPlan(string updatesRoot, string? attemptId)
    {
        if (!AgentUpdateSecurity.IsSafeAttemptId(attemptId))
            return null;

        var directory = Path.Combine(updatesRoot, "attempts", AgentUpdateSecurity.AttemptDirectoryPrefix + attemptId);
        var path = Path.Combine(directory, AgentUpdateSecurity.PlanFileName);
        var plan = AgentUpdateDurableFile.Read<AgentUpdatePlan>(path, updatesRoot);
        if (plan is null)
            return null;

        if (plan.SchemaVersion != AgentUpdaterContract.PlanSchema || plan.AttemptId != attemptId ||
            !string.Equals(plan.ArtifactKind, "msi", StringComparison.OrdinalIgnoreCase) || plan.Sequence <= 0 ||
            !AgentUpdateManifestValidator.IsReleaseVersion(plan.Version) ||
            !AgentUpdateManifestValidator.IsSha256(plan.ManifestDigest) ||
            !string.Equals(plan.ManifestPath, Path.Combine(directory, AgentUpdateSecurity.ManifestFileName), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Installed attempt plan is invalid.");

        return plan;
    }

    internal static Inspection? Inspect(string updatesRoot, AgentUpdatePlan? plan, string? installedVersion,
        IReadOnlyList<string> manifestKeys)
    {
        if (plan?.ManifestPath is not { } path || !string.Equals(plan.Version, installedVersion, StringComparison.Ordinal))
            return null;

        AgentUpdateSecurity.ValidateTrustedPath(path, updatesRoot, allowMissing: false);
        var manifest = AgentUpdateManifestValidator.VerifyStoredSignature(
            Encoding.UTF8.GetString(AgentUpdateLkgStore.ReadSmallFile(path)), manifestKeys);
        var digest = AgentUpdateManifestValidator.Digest(manifest);
        if (manifest.Version != installedVersion || manifest.Sequence != plan.Sequence || manifest.Channel != plan.Channel ||
            !string.Equals(plan.ManifestDigest, digest, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Stored manifest does not match the installed attempt.");

        var floor = AgentUpdateRollbackFloor.Read(updatesRoot);
        if (manifest.MinRollbackVersion is not { } minimum ||
            string.Equals(floor?.ManifestDigest, digest, StringComparison.OrdinalIgnoreCase) ||
            floor is not null && AgentVersionComparer.CompareReleaseCore(minimum, floor.MinVersion) is not > 0)
            return new(Pending: null);

        return new(new(minimum, manifest.Sequence, digest));
    }

    // The host rereads the journal, plan and signed candidate after taking host.lock.
    internal static bool Apply(string updatesRoot, Candidate candidate, DateTimeOffset now)
        => AgentUpdateRollbackFloor.Raise(updatesRoot, candidate.MinimumVersion, "signed_manifest", candidate.Sequence,
            candidate.ManifestDigest, now);
}
