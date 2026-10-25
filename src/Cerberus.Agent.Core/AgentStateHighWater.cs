using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

/// <summary>
/// The highest <c>state_seq</c> a signed-state store accepted for one agent id, kept in its own small file next to
/// the state file (<c>agent-state.v1.json.seq</c>). It survives the reset of a corrupt state file, so replayed signed
/// state at or below it stays stale. A missing, untrusted or unreadable file reads as no high-water mark (the
/// behaviour before the file existed). Written with the same protected writer as the state file.
/// </summary>
internal sealed class AgentStateHighWater
{
    public const string Suffix = ".seq";
    private const long MaxFileBytes = 4096;
    private const string Schema = "cerberus.agent-state-seq.v1";

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    private readonly string _path;
    private readonly ProtectedMachineFile _file;
    private readonly IAgentLogger _log;

    public AgentStateHighWater(string statePath, IAgentLogger log, bool enforceFileProvenance)
    {
        _path = statePath + Suffix;
        _file = new ProtectedMachineFile(_path, enforceFileProvenance);
        _log = log;
    }

    public (string AgentId, long Seq)? Read()
    {
        try
        {
            _file.ValidateDirectory();
            if (!_file.Exists())
                return null;
            _file.ValidateFile();
            if (new FileInfo(_path).Length > MaxFileBytes)
                return null;
            var file = JsonSerializer.Deserialize<HighWaterFile>(File.ReadAllBytes(_path), JsonOpts);
            return file is { Schema: Schema, AgentId.Length: > 0, StateSeq: >= 0 } ? (file.AgentId, file.StateSeq) : null;
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex) || ex is JsonException)
        {
            _log.Warn($"Signed agent state high-water mark unreadable ({ex.GetType().Name}).");
            return null;
        }
    }

    public bool TryWrite(string agentId, long seq)
    {
        var tempPath = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            _file.EnsureDirectory();
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new HighWaterFile(Schema, agentId, seq), JsonOpts);
            using (var stream = _file.CreateTemp(tempPath))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            File.Move(tempPath, _path, overwrite: true);
            return true;
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex))
        {
            _log.Warn($"Signed agent state high-water mark write failed: {ex.GetType().Name}.");
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

    private sealed record HighWaterFile(
        [property: JsonPropertyName("schema")] string Schema,
        [property: JsonPropertyName("agent_id")] string AgentId,
        [property: JsonPropertyName("state_seq")] long StateSeq);
}
