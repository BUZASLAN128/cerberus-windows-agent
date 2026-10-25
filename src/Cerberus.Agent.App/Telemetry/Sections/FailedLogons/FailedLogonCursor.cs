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

    /// <summary>Whether the decision means events may have been missed (reported as <c>cursor_reset</c>).</summary>
    internal static bool IsReset(ChannelStart decision) => decision is ChannelStart.Reset or ChannelStart.Gap;
}

/// <summary>Cursor file in the agent data directory (<c>failed-logons-cursor.v1.json</c>), written atomically.</summary>
internal sealed class FailedLogonCursorStore
{
    internal const string FileName = "failed-logons-cursor.v1.json";

    private readonly string _path;

    public FailedLogonCursorStore(string? path = null)
    {
        _path = path ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            AgentInstallIdentity.DataDirName,
            FileName);
    }

    /// <summary>Missing file gives a fresh state (first run); an unreadable or malformed file gives <paramref name="invalid"/>=true.</summary>
    public FailedLogonCursorState Load(out bool invalid)
    {
        invalid = false;
        try
        {
            if (!File.Exists(_path))
                return new FailedLogonCursorState();
            var info = new FileInfo(_path);
            if (info.Length > 64 * 1024)
            {
                invalid = true;
                return new FailedLogonCursorState();
            }
            var state = JsonSerializer.Deserialize<FailedLogonCursorState>(File.ReadAllText(_path));
            if (state is null || state.Version != 1 || state.Channels is null)
            {
                invalid = true;
                return new FailedLogonCursorState();
            }
            state.Channels = new Dictionary<string, long>(state.Channels, StringComparer.OrdinalIgnoreCase);
            return state;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            invalid = true;
            return new FailedLogonCursorState();
        }
    }

    /// <summary>Returns false when the state could not be written (the next window then repeats; never throws).</summary>
    public bool Save(FailedLogonCursorState state)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var temp = _path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(state));
            File.Move(temp, _path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
