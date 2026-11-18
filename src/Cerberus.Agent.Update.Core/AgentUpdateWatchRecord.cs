using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

internal static class AgentUpdateWatchOutcomes
{
    public const string Open = "open";
    public const string Passed = "passed";
    public const string RollbackPending = "rollback_pending";
    public const string RolledBack = "rolled_back";
    public const string RollbackFailed = AgentUpdateWatchJournal.RollbackFailed;
    public const string ForwardOnlyFailed = "forward_only_failed";
    public const string Superseded = "superseded";
    public const string Inconclusive = "inconclusive";

    public static bool IsKnown(string? outcome) => outcome is Open or Passed or RollbackPending or RolledBack or
        RollbackFailed or ForwardOnlyFailed or Superseded or Inconclusive;
}

internal sealed record AgentUpdateWatchSegment(string BootId, long ObservedMs);

internal sealed record AgentUpdateWatchLastSample(string BootId, int? Pid, DateTimeOffset? ProcessStartUtc,
    AgentUpdateWatchServiceState State, int Win32Exit, int SvcExit);

internal sealed record AgentUpdateWatchRecord(
    string Schema,
    string AttemptId,
    string WatchedVersion,
    long WatchedSequence,
    Guid WatchedProductCode,
    string? ReplacedVersion,
    string? LkgVersion,
    DateTimeOffset StartedUtc,
    IReadOnlyList<AgentUpdateWatchSegment> Segments,
    AgentUpdateWatchLastSample? LastSample,
    int CrashRestarts,
    int ImageMismatchStreak,
    long? ExeSize,
    DateTimeOffset? ExeMtime,
    string Outcome,
    IReadOnlyList<string> Alerts)
{
    public const string CurrentSchema = "agent.update.watch.v1";

    internal void Validate()
    {
        if (Schema != CurrentSchema || !AgentUpdateSecurity.IsSafeAttemptId(AttemptId) ||
            !AgentUpdateManifestValidator.IsReleaseVersion(WatchedVersion) || WatchedSequence <= 0 ||
            WatchedProductCode == Guid.Empty || !ValidOptionalVersion(ReplacedVersion) || !ValidOptionalVersion(LkgVersion) ||
            !IsUtc(StartedUtc) || CrashRestarts < 0 || ImageMismatchStreak < 0 || ExeSize is < 0 ||
            ExeMtime is { } mtime && !IsUtc(mtime) || !AgentUpdateWatchOutcomes.IsKnown(Outcome) ||
            Alerts is null || Alerts.Any(code => code is null || !AgentUpdateErrorCodes.IsCode(code)) ||
            Segments is null)
            throw InvalidWatch();

        var bootIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var segment in Segments)
        {
            if (segment is null || segment.ObservedMs < 0 || !Guid.TryParseExact(segment.BootId, "N", out var bootId) ||
                bootId == Guid.Empty || !bootIds.Add(segment.BootId))
                throw InvalidWatch();
        }

        if (LastSample is { } sample && (!bootIds.Contains(sample.BootId) || sample.Pid is <= 0 ||
            sample.ProcessStartUtc is { } started && (sample.Pid is null || !IsUtc(started)) ||
            !Enum.IsDefined(sample.State)))
            throw InvalidWatch();
    }

    private static bool ValidOptionalVersion(string? value) => value is null || AgentUpdateManifestValidator.IsReleaseVersion(value);
    private static bool IsUtc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static InvalidOperationException InvalidWatch() => new("Update watch record is invalid.");
}

internal static class AgentUpdateWatchStore
{
    public const string FileName = "watch.json";

    private static readonly JsonSerializerOptions RecordJson = new(AgentUpdateLkgStore.RecordJson)
    {
        RespectRequiredConstructorParameters = true,
        Converters = { new JsonStringEnumConverter<AgentUpdateWatchServiceState>(JsonNamingPolicy.SnakeCaseLower, allowIntegerValues: false) },
    };

    public static AgentUpdateWatchRecord? Read(string updatesRoot)
    {
        var root = AgentUpdateSecurity.NormalizeRoot(updatesRoot);
        var path = Path.Combine(root, AgentUpdateLkgStore.DirectoryName, FileName);
        AgentUpdateSecurity.ValidateTrustedPath(path, root, allowMissing: true);
        try
        {
            var record = JsonSerializer.Deserialize<AgentUpdateWatchRecord>(AgentUpdateLkgStore.ReadSmallFile(path), RecordJson)
                ?? throw new InvalidOperationException("Update watch record is empty.");
            record.Validate();
            return record;
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        catch (JsonException ex) { throw new InvalidOperationException("Update watch record is corrupt.", ex); }
    }

    /// <summary>The host writes under host.lock. Service readers do not take the host lock.</summary>
    public static void Write(string updatesRoot, AgentUpdateWatchRecord record)
    {
        record.Validate();
        var root = AgentUpdateSecurity.NormalizeRoot(updatesRoot);
        var path = Path.Combine(root, AgentUpdateLkgStore.DirectoryName, FileName);
        AgentUpdateDurableFile.Write(path, root, JsonSerializer.SerializeToElement(record, RecordJson));
    }
}
