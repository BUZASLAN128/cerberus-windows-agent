using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public sealed partial class CommandReplayStore
{
    private bool _legacyBindingUnavailable;
    private string? _legacyBoundAgentId;
    private const string BindingSchema = "cerberus.legacy-replay-enrollment.v1";
    private static readonly JsonSerializerOptions BindingJson = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 4,
    };

    /// <summary>
    /// Called only from the service's protected credential/lifecycle snapshot, never from a command.
    /// Preserve the original store on adoption. A verified new enrollment with a new agent id gets
    /// its own durable store; returning to an earlier id reuses that id's store, including its reset.
    /// No replay history or reset marker is cleared.
    /// </summary>
    public static CommandReplayStore OpenLegacyAsyncForEnrollment(AgentIdentity identity,
        AgentLifecycleSnapshot lifecycle, IAgentLogger? log = null, string? originalPath = null)
    {
        log ??= NullAgentLogger.Instance;
        originalPath ??= DefaultLegacyAsyncPath();
        var blocked = new CommandReplayStore(originalPath, log: log)
        {
            _legacyBindingUnavailable = true,
            _legacyBoundAgentId = identity.AgentId,
        };
        var path = originalPath + ".enrollment";
        var file = new ProtectedMachineFile(path);
        var temp = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            var current = new LegacyRegistration(identity, lifecycle.Generation, lifecycle.LastEnrollmentNonce);
            if (!Valid(current) || !lifecycle.QuiescenceComplete || !AgentLifecycleStates.AllowsAutomaticNetwork(lifecycle.State))
                throw new InvalidDataException("Enrollment snapshot is not active.");
            file.ValidateDirectory();
            LegacyBinding binding;
            var changed = false;
            if (file.Exists())
            {
                file.ValidateFile();
                using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                if (input.Length is <= 0 or > 4096) throw new InvalidDataException("Invalid enrollment binding size.");
                binding = JsonSerializer.Deserialize<LegacyBinding>(input, BindingJson)
                    ?? throw new InvalidDataException("Missing enrollment binding.");
                if (binding.Schema != BindingSchema || !Valid(binding.Original) || !Valid(binding.Current))
                    throw new InvalidDataException("Invalid enrollment binding.");
                if (current.Identity != binding.Current.Identity)
                {
                    // A token refresh, restart, arbitrary id, or lifecycle transition is not enrollment proof.
                    if (current.Identity.AgentId == binding.Current.Identity.AgentId ||
                        current.Generation <= binding.Current.Generation ||
                        !Guid.TryParseExact(current.Nonce, "N", out _) || current.Nonce == binding.Current.Nonce)
                        throw new InvalidDataException("A new verified registration is required.");
                    binding = binding with { Current = current };
                    changed = true;
                }
                else if (current.Generation < binding.Current.Generation)
                    throw new InvalidDataException("Stale enrollment snapshot.");
            }
            else
            {
                file.EnsureDirectory();
                if (Directory.EnumerateFiles(Path.GetDirectoryName(Path.GetFullPath(path))!,
                        Path.GetFileNameWithoutExtension(originalPath) + "-enrolled-*.json*").Any())
                    throw new InvalidDataException("Enrollment binding is missing beside registered replay stores.");
                binding = new LegacyBinding(BindingSchema, current, current);
                changed = true;
            }
            if (changed)
            {
                file.EnsureDirectory();
                using (var output = file.CreateTemp(temp))
                {
                    output.Write(JsonSerializer.SerializeToUtf8Bytes(binding, BindingJson));
                    output.Flush(flushToDisk: true);
                }
                File.Move(temp, path, overwrite: true);
            }
            var storePath = current.Identity == binding.Original.Identity ? originalPath :
                Path.Combine(Path.GetDirectoryName(Path.GetFullPath(originalPath))!,
                    Path.GetFileNameWithoutExtension(originalPath) + "-enrolled-" +
                    Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(current.Identity))) + ".json");
            var store = new CommandReplayStore(storePath, log: log) { _legacyBoundAgentId = identity.AgentId };
            if (!store.IsAvailable || store.ResetAt != 0)
                log.Warn("Async commands disabled: replay state is unavailable or reset; recovery requires verified re-enrollment with a new agent identity.");
            return store;
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex) || ex is JsonException or InvalidDataException)
        {
            log.Warn($"Async commands disabled: enrollment replay binding unavailable ({ex.GetType().Name}); verified re-enrollment with a new agent identity is required.");
            try { File.Delete(temp); }
            catch (Exception cleanup) when (ProtectedMachineFile.IsFailure(cleanup)) { }
            return blocked;
        }
    }

    internal bool AllowsLegacyAgent(string agentId)
        => !_legacyBindingUnavailable && (_legacyBoundAgentId is null || _legacyBoundAgentId == agentId);

    private static bool Valid(LegacyRegistration? registration)
        => registration is not null && registration.Identity is { Product: AgentProducts.Cerberus } identity &&
           !string.IsNullOrWhiteSpace(identity.AgentId) && identity.AgentId.Length <= 256 &&
           !string.IsNullOrWhiteSpace(identity.TenantId) && identity.TenantId.Length <= 256 && registration.Generation >= 0 &&
           (registration.Nonce is null || Guid.TryParseExact(registration.Nonce, "N", out _));

    private sealed record LegacyRegistration(AgentIdentity Identity, long Generation, string? Nonce);
    private sealed record LegacyBinding(string Schema, LegacyRegistration Original, LegacyRegistration Current);
}
