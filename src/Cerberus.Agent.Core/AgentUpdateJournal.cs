using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cerberus.Agent.Core;

/// <summary>
/// Internal journal data used while a staged attempt awaits trusted manifest
/// identity verification. It is not a public update-state protocol.
/// </summary>
public sealed record AgentUpdateReconciliationSnapshot(
    string Phase,
    long LifecycleGeneration,
    bool Automatic,
    bool Required,
    DateTimeOffset? ApplyNotBeforeUtc,
    int RetryCount,
    DateTimeOffset? NextRetryUtc,
    DateTimeOffset? NextCheckUtc);

/// <summary>One machine update decision. Installer progress is evidence, never permission to launch again.</summary>
public sealed record AgentUpdateJournal
{
    public string SchemaVersion { get; init; } = "agent.update.journal.v1";
    public long Revision { get; init; }
    public string ScheduleSeed { get; init; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset? NextCheckUtc { get; init; }
    public string? AttemptId { get; init; }
    public string Phase { get; init; } = AgentUpdateStates.NotChecked;
    public long LifecycleGeneration { get; init; }
    public bool Automatic { get; init; }
    public bool Required { get; init; }
    public DateTimeOffset? ApplyNotBeforeUtc { get; init; }
    public int RetryCount { get; init; }
    public DateTimeOffset? NextRetryUtc { get; init; }
    /// <summary>Generation that authorized the durable required-policy provenance, when present.</summary>
    public long? RequiredPolicyGeneration { get; init; }
    public int? RunnerProcessId { get; init; }
    public DateTimeOffset? RunnerStartedUtc { get; init; }
    public int? InstallerProcessId { get; init; }
    public DateTimeOffset? InstallerStartedUtc { get; init; }
    public string? InstallationBootId { get; init; }
    public AgentUpdateInstallerResult? InstallerResult { get; init; }
    public AgentUpdateReconciliationSnapshot? ReconciliationSnapshot { get; init; }
    public long HealthyInstalledSequence { get; init; }
    public string? HealthyInstalledVersion { get; init; }

    public bool MayHaveStartedInstallation => Phase is "install_may_have_started" or "installing" or
        "health_pending" or "pending_reboot" or "recovery_required";

    public bool HasUnfinishedAttempt => AttemptId is not null && Phase is not
        (AgentUpdateStates.Current or AgentUpdateStates.Installed or AgentUpdateStates.Failed or AgentUpdateStates.Quarantined or AgentUpdateStates.Blocked);
}

/// <summary>Flush-before-replace journal with short cross-process locking. Never hold its lock over network, MSI or health I/O.</summary>
public sealed class AgentUpdateJournalStore
{
    private readonly string _root;
    private readonly string _path;
    public AgentUpdateJournalStore(string root)
    {
        _root = AgentUpdateSecurity.NormalizeRoot(root);
        _path = Path.Combine(_root, "transaction.json");
    }

    public AgentUpdateJournal Read()
    {
        var value = AgentUpdateDurableFile.Read<AgentUpdateJournal>(_path, _root);
        if (value is null)
            return new AgentUpdateJournal();
        if (value.SchemaVersion != "agent.update.journal.v1" || value.Revision < 0 ||
            !KnownPhase(value.Phase) ||
            value.RetryCount is < 0 or > 3 || string.IsNullOrWhiteSpace(value.ScheduleSeed) ||
            (value.AttemptId is not null && !AgentUpdateSecurity.IsSafeAttemptId(value.AttemptId)) ||
            value.RequiredPolicyGeneration is < 0 ||
            (value.RequiredPolicyGeneration is not null && !value.Required) ||
            !ValidReconciliationSnapshot(value.ReconciliationSnapshot))
            throw new InvalidOperationException("Update journal is invalid.");
        return value;
    }

    private static bool ValidReconciliationSnapshot(AgentUpdateReconciliationSnapshot? snapshot)
        => snapshot is null ||
           (snapshot.Phase is AgentUpdateStates.Checking or AgentUpdateStates.Downloading or AgentUpdateStates.Staged or
               AgentUpdateStates.AwaitingConsent or AgentUpdateStates.RetryableBusy or AgentUpdateStates.Available) &&
           snapshot.LifecycleGeneration >= 0 &&
           snapshot.RetryCount is >= 0 and <= 3;

    private static bool KnownPhase(string phase) => phase is AgentUpdateStates.NotChecked or AgentUpdateStates.Current or
        AgentUpdateStates.Available or AgentUpdateStates.Checking or AgentUpdateStates.Downloading or AgentUpdateStates.Staged or
        AgentUpdateStates.AwaitingConsent or AgentUpdateStates.Installing or AgentUpdateStates.HealthPending or AgentUpdateStates.PendingReboot or
        AgentUpdateStates.Installed or AgentUpdateStates.RetryableBusy or AgentUpdateStates.RecoveryRequired or AgentUpdateStates.Quarantined or
        AgentUpdateStates.Failed or AgentUpdateStates.Blocked or "launch_requested" or "install_may_have_started";

    public AgentUpdateJournal Change(Func<AgentUpdateJournal, AgentUpdateJournal> change)
    {
        using var gate = AgentUpdateSecurity.AcquireGlobalLock(_root);
        var before = Read();
        var after = change(before) with { Revision = checked(before.Revision + 1) };
        AgentUpdateDurableFile.Write(_path, _root, after);
        return after;
    }

    public AgentUpdateJournal ChangeAttempt(string attemptId, Func<AgentUpdateJournal, AgentUpdateJournal> change)
        => Change(before => before.AttemptId == attemptId
            ? change(before)
            : throw new InvalidOperationException("Update attempt is no longer active."));

    public static TimeSpan Offset(string seed, TimeSpan maximum)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var number = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        return TimeSpan.FromSeconds(number % ((ulong)maximum.TotalSeconds + 1));
    }
}

/// <summary>Small protected JSON records. Malformed, oversized or unreadable data is a hard failure.</summary>
public static class AgentUpdateDurableFile
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
    public const int MaxBytes = 256 * 1024;

    public static T? Read<T>(string path, string root) where T : class
    {
        AgentUpdateSecurity.ValidateTrustedPath(path, root, allowMissing: true);
        if (!File.Exists(path))
            return null;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (stream.Length is <= 0 or > MaxBytes)
            throw new InvalidOperationException("Update record length is invalid.");
        try
        {
            return JsonSerializer.Deserialize<T>(stream, Options)
                ?? throw new InvalidOperationException("Update record is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException("Update record is corrupt.", ex);
        }
    }

    public static void Write<T>(string path, string root, T value)
    {
        AgentUpdateSecurity.ValidateTrustedPath(path, root, allowMissing: true);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Options);
        if (bytes.Length > MaxBytes)
            throw new InvalidOperationException("Update record is too large.");
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}
