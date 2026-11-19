using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public static class AgentLifecycleFile
{
    public const string SchemaVersion = "cerberus-agent-lifecycle.v1";
    public const int MaxStateFileBytes = 16 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static string DefaultPath
        => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            AgentInstallIdentity.DataDirName,
            "Privileged",
            "lifecycle-state.json");

    [SupportedOSPlatform("windows")]
    public static void ValidateProductionPath(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (string.IsNullOrWhiteSpace(directory))
            throw ProtectionFailure();
        try
        {
            AgentUpdateSecurity.ValidateProtectedPath(directory, directory, allowMissing: true);
            AgentUpdateSecurity.ValidateProtectedPath(path, directory, allowMissing: true);
            if (File.Exists(path))
                ValidateLifecycleFile(path);
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch
        {
            throw ProtectionFailure();
        }
    }

    public static bool TryParse(string raw, out AgentLifecycleSnapshot snapshot)
    {
        snapshot = Corrupt();
        AgentLifecyclePayload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<AgentLifecyclePayload>(raw, JsonOptions);
        }
        catch (JsonException)
        {
            return false;
        }

        if (payload is null || payload.Generation < 0 || payload.Revision < 0 ||
            !string.Equals(payload.SchemaVersion, SchemaVersion, StringComparison.Ordinal) ||
            !Enum.TryParse<AgentLifecycleState>(payload.State, ignoreCase: true, out var state) ||
            !Enum.IsDefined(state))
            return false;

        snapshot = new AgentLifecycleSnapshot(
            state,
            payload.ReasonCode,
            payload.LastRequestId,
            payload.NextAttemptUtc,
            payload.GenericAuthFailureCount,
            payload.UpdatedAtUtc)
        {
            Generation = payload.Generation,
            Revision = payload.Revision,
            QuiescenceComplete = payload.QuiescenceComplete ?? AgentLifecycleStates.AllowsAutomaticNetwork(state),
            TransientFailureCount = payload.TransientFailureCount,
            LastEnrollmentNonce = payload.LastEnrollmentNonce,
        };
        return true;
    }

    public static AgentLifecycleSnapshot Corrupt()
        => new(
            State: AgentLifecycleState.BlockedConfig,
            ReasonCode: "lifecycle_state_invalid",
            LastRequestId: null,
            NextAttemptUtc: null,
            GenericAuthFailureCount: 0,
            UpdatedAtUtc: DateTimeOffset.UtcNow) { QuiescenceComplete = false };

    [SupportedOSPlatform("windows")]
    public static AgentLifecycleSnapshot ReadProduction()
    {
        var path = DefaultPath;
        ValidateProductionPath(path);
        if (!File.Exists(path))
            return new AgentLifecycleSnapshot();

        try
        {
            if (new FileInfo(path).Length > MaxStateFileBytes)
                return Corrupt();
            TryParse(File.ReadAllText(path), out var snapshot);
            return snapshot;
        }
        catch
        {
            return Corrupt();
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateLifecycleFile(string path)
    {
        var rules = new FileInfo(path).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid)) continue;
            if (!sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
                (rule.FileSystemRights & ~(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize)) != 0)
                throw ProtectionFailure();
        }
    }

    private static InvalidOperationException ProtectionFailure()
        => new("Cerberus agent lifecycle state protection could not be established.");
}

public sealed record AgentLifecyclePayload(
    [property: JsonPropertyName("schema_version")] string SchemaVersion,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("reason_code")] string? ReasonCode,
    [property: JsonPropertyName("last_request_id")] string? LastRequestId,
    [property: JsonPropertyName("next_attempt_utc")] DateTimeOffset? NextAttemptUtc,
    [property: JsonPropertyName("generic_auth_failure_count")] int GenericAuthFailureCount,
    [property: JsonPropertyName("updated_at_utc")] DateTimeOffset UpdatedAtUtc,
    [property: JsonPropertyName("generation")] long Generation = 0,
    [property: JsonPropertyName("quiescence_complete")] bool? QuiescenceComplete = null,
    [property: JsonPropertyName("transient_failure_count")] int TransientFailureCount = 0,
    [property: JsonPropertyName("revision")] long Revision = 0,
    [property: JsonPropertyName("last_enrollment_nonce")] string? LastEnrollmentNonce = null);
