using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

/// <summary>Persisted read position: last handled record id per channel and the end of the last window. No account data.</summary>
internal sealed class FailedLogonCursorState
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("last_window_end_utc")]
    public DateTimeOffset? LastWindowEndUtc { get; set; }

    [JsonPropertyName("channels")]
    public Dictionary<string, long> Channels { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

internal enum ChannelStart
{
    /// <summary>No saved position (first run): start at the current end of the log, no history backfill.</summary>
    FirstRun,
    /// <summary>Continue after the saved record id.</summary>
    Resume,
    /// <summary>Saved position unusable (log cleared / ids regressed / state file invalid): start at the current end.</summary>
    Reset,
    /// <summary>Records between the saved id and the oldest retained one were overwritten: resume from the oldest retained record.</summary>
    Gap,
}

internal static class FailedLogonCursorLogic
{
    /// <summary>
    /// Decides where a channel read starts. <paramref name="saved"/> is null when the channel has no saved position;
    /// <paramref name="oldestRecordId"/> / <paramref name="newestRecordId"/> bound the records now in the log (0 when empty).
    /// A first run starts at "now" and is not a reset; a saved id above the newest id means the log was cleared; a saved id
    /// below <c>oldest - 1</c> means the log wrapped and events were lost. When the whole state file is invalid every
    /// channel is a reset, which the caller passes as <paramref name="stateInvalid"/>.
    /// </summary>
    internal static ChannelStart Decide(long? saved, long oldestRecordId, long newestRecordId, bool stateInvalid)
    {
        if (stateInvalid)
            return ChannelStart.Reset;
        if (saved is null)
            return ChannelStart.FirstRun;
        if (saved.Value > newestRecordId)
            return ChannelStart.Reset;
        return saved.Value < oldestRecordId - 1 ? ChannelStart.Gap : ChannelStart.Resume;
    }

    /// <summary>Record id after which to read; records at or below it are never read.</summary>
    internal static long StartAfter(ChannelStart decision, long? saved, long oldestRecordId, long newestRecordId) => decision switch
    {
        ChannelStart.Resume => saved!.Value,
        ChannelStart.Gap => oldestRecordId - 1,
        _ => newestRecordId,
    };

    /// <summary>
    /// Position to save after a read. An uncapped read saw everything up to the log end captured before it, so the
    /// cursor moves there even when no record matched (a full circular log with rare matches would otherwise look
    /// wrapped every window); a capped read stops at the last record it handled.
    /// </summary>
    internal static long NextSaved(long lastRecordId, bool capped, long newestBeforeRead)
        => capped ? lastRecordId : Math.Max(lastRecordId, newestBeforeRead);

    /// <summary>Whether the decision means events may have been missed (reported as <c>cursor_reset</c>).</summary>
    internal static bool IsReset(ChannelStart decision) => decision is ChannelStart.Reset or ChannelStart.Gap;
}

/// <summary>
/// Cursor file <c>&lt;DataDir&gt;\Privilegedailed-logons-cursor.v1.json</c>, kept through <see cref="ProtectedMachineFile"/>:
/// trusted directory chain, owner and DACL, no reparse point, new files created with a SYSTEM/Administrators-only DACL
/// under a unique temp name and moved over the target. Anything that fails validation or parsing is never trusted.
/// </summary>
internal sealed class FailedLogonCursorStore
{
    internal const string FileName = "failed-logons-cursor.v1.json";
    private const long MaxFileBytes = 64 * 1024;

    private readonly string _path;
    private readonly ProtectedMachineFile _file;

    public FailedLogonCursorStore(string? path = null)
    {
        _path = path ?? ProtectedMachineFile.DefaultPath(FileName);
        _file = new ProtectedMachineFile(_path);
    }

    /// <summary>Missing file gives a fresh state (first run); an untrusted, unreadable or malformed file gives <paramref name="invalid"/>=true.</summary>
    public FailedLogonCursorState Load(out bool invalid)
    {
        invalid = false;
        try
        {
            _file.ValidateDirectory();
            if (!_file.Exists())
                return new FailedLogonCursorState();
            _file.ValidateFile();
            if (new FileInfo(_path).Length <= MaxFileBytes
                && JsonSerializer.Deserialize<FailedLogonCursorState>(File.ReadAllBytes(_path)) is { Version: 1, Channels: not null } state)
            {
                state.Channels = new Dictionary<string, long>(state.Channels, StringComparer.OrdinalIgnoreCase);
                return state;
            }
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex) || ex is JsonException)
        {
        }
        invalid = true;
        return new FailedLogonCursorState();
    }

    /// <summary>Returns false when the state could not be written (the next window then repeats; never throws).</summary>
    public bool Save(FailedLogonCursorState state)
    {
        var tempPath = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            _file.EnsureDirectory();
            using (var stream = _file.CreateTemp(tempPath))
            {
                stream.Write(JsonSerializer.SerializeToUtf8Bytes(state));
                stream.Flush(flushToDisk: true);
            }
            File.Move(tempPath, _path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex))
        {
            try
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
            catch (Exception cleanup) when (cleanup is IOException or UnauthorizedAccessException)
            {
                // The temp name is unique; a leftover file is never read.
            }
            return false;
        }
    }
}
