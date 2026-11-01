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
    /// Preserve every prior store. A verified new nonce, generation and key binding creates
    /// a new replay epoch, including when the backend reuses the same agent id.
    /// No replay history or reset marker is cleared.
    /// </summary>
    public static CommandReplayStore OpenLegacyAsyncForEnrollment(AgentIdentity identity,
        AgentLifecycleSnapshot lifecycle, IAgentLogger? log = null, string? originalPath = null,
        string? keyFingerprint = null)
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
            var current = new LegacyRegistration(identity, lifecycle.Generation, lifecycle.LastEnrollmentNonce, keyFingerprint);
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
                if (binding.CurrentEpoch is not null && (!VerifiedEpoch(binding.Current) || binding.CurrentEpoch != Epoch(binding.Current)))
                    throw new InvalidDataException("Invalid replay epoch binding.");
                if (!binding.ReplayInitialized && !VerifiedEpoch(binding.Current))
                    throw new InvalidDataException("Replay initialization requires a verified enrollment.");
                if (current.Identity != binding.Current.Identity || current.Nonce != binding.Current.Nonce ||
                    (binding.Current.KeyFingerprint is not null && current.KeyFingerprint != binding.Current.KeyFingerprint))
                {
                    // A token refresh, restart, arbitrary id, or lifecycle transition is not enrollment proof.
                    if (current.Generation <= binding.Current.Generation || !VerifiedEpoch(current) ||
                        current.Nonce == binding.Current.Nonce)
                        throw new InvalidDataException("A new verified registration is required.");
                    binding = binding with { Current = current, CurrentEpoch = Epoch(current), ReplayInitialized = false };
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
                binding = new LegacyBinding(BindingSchema, current, current, ReplayInitialized: !VerifiedEpoch(current));
                changed = true;
            }
            if (changed) WriteBinding();
            var storePath = binding.CurrentEpoch is null && current.Identity == binding.Original.Identity ? originalPath :
                Path.Combine(Path.GetDirectoryName(Path.GetFullPath(originalPath))!,
                    Path.GetFileNameWithoutExtension(originalPath) + "-enrolled-" +
                    (binding.CurrentEpoch ?? Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(current.Identity)))) + ".json");
            // Only a durable, not-yet-admitted verified epoch can initialize an empty file.
            // After admission, absence is loss, never evidence of a new installation.
            var store = new CommandReplayStore(storePath, log: log, enrollmentEstablished: binding.ReplayInitialized)
                { _legacyBoundAgentId = identity.AgentId };
            if (!binding.ReplayInitialized && store.IsAvailable && store.ResetAt == 0)
            {
                if (!store._file.Exists() && !store.TryPersist(store._records, 0))
                    throw new IOException("Replay epoch initialization failed.");
                binding = binding with { ReplayInitialized = true };
                WriteBinding();
            }
            if (!store.IsAvailable || store.ResetAt != 0)
                log.Warn("Async commands disabled: replay state is unavailable or reset; recovery requires verified re-enrollment.");
            return store;

            void WriteBinding()
            {
                file.EnsureDirectory();
                using (var output = file.CreateTemp(temp))
                {
                    output.Write(JsonSerializer.SerializeToUtf8Bytes(binding, BindingJson));
                    output.Flush(flushToDisk: true);
                }
                File.Move(temp, path, overwrite: true);
            }
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex) || ex is JsonException or InvalidDataException)
        {
            log.Warn($"Async commands disabled: enrollment replay binding unavailable ({ex.GetType().Name}); verified re-enrollment is required.");
            try { File.Delete(temp); }
            catch (Exception cleanup) when (ProtectedMachineFile.IsFailure(cleanup))
            {
                log.Warn($"Replay binding temporary file cleanup failed: {cleanup.GetType().Name}.");
            }
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

    private static bool VerifiedEpoch(LegacyRegistration registration)
        => registration.Generation > 0 && Guid.TryParseExact(registration.Nonce, "N", out _) &&
           registration.KeyFingerprint is { Length: 71 } fingerprint && fingerprint.StartsWith(AgentKeyFingerprint.Prefix, StringComparison.Ordinal) &&
           fingerprint[AgentKeyFingerprint.Prefix.Length..].All(char.IsAsciiHexDigit);

    private static string Epoch(LegacyRegistration registration)
        => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(registration)));

    private sealed record LegacyRegistration(AgentIdentity Identity, long Generation, string? Nonce, string? KeyFingerprint = null);
    private sealed record LegacyBinding(string Schema, LegacyRegistration Original, LegacyRegistration Current,
        string? CurrentEpoch = null, bool ReplayInitialized = true);
}
