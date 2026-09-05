using System.Security.Cryptography;
using System.Text.Json;

namespace Cerberus.Agent.Core;

public sealed record AgentUpdateTrust(
    IReadOnlyList<string> ManifestPublicKeyPems,
    string ExpectedChannel,
    IReadOnlyList<string> AllowedArtifactPrefixes,
    string CurrentVersion,
    bool AllowRollbackManifest = false,
    bool AllowChannelDowngrade = false,
    long MaxArtifactBytes = 200 * 1024 * 1024,
    string? ConfiguredManifestUrl = null,
    string? AllowedSignerKeyIdentity = null,
    bool AllowUnsignedDevBuild = false,
    bool RequireManifestV2 = false,
    bool RequireBitsDownloader = false,
    bool RequireSystemAuthority = false);

public sealed record AgentUpdateSignal(
    bool Required,
    bool Recommended,
    string? ManifestUrl,
    string? Reason,
    string? Channel);

public sealed record AgentUpdatePlan(
    string ArtifactKind,
    string Version,
    string Channel,
    string ArtifactPath,
    string Sha256,
    string StagedAtUtc,
    string Reason,
    string SchemaVersion = "agent.update.plan.v2",
    string? AttemptId = null,
    long Sequence = 0,
    string? ExpiresAtUtc = null,
    long? ArtifactLength = null,
    string? ManifestPath = null,
    string? SignerKeyIdentity = null,
    bool Required = false,
    bool RollbackAllowed = false,
    int RetryCount = 0);

public sealed record AgentUpdateCheckResult(
    bool Available,
    bool Required,
    bool Recommended,
    string? Version,
    string? Channel,
    string? Reason,
    string? ManifestUrl,
    string? ArtifactKind)
{
    public static AgentUpdateCheckResult None { get; } = new(
        Available: false,
        Required: false,
        Recommended: false,
        Version: null,
        Channel: null,
        Reason: null,
        ManifestUrl: null,
        ArtifactKind: null);
}

public sealed class AgentUpdateStager
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private readonly HttpClient _http;
    private readonly AgentUpdateTrust _trust;
    private readonly string _stagingRoot;
    private readonly IAgentLogger _log;

    public static string DefaultStagingRoot => AgentUpdateSecurity.DefaultPrivilegedRoot;

    public AgentUpdateStager(HttpClient http, AgentUpdateTrust trust, string stagingRoot, IAgentLogger? log = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _trust = trust ?? throw new ArgumentNullException(nameof(trust));
        _stagingRoot = AgentUpdateSecurity.NormalizeRoot(stagingRoot);
        _log = log ?? NullAgentLogger.Instance;
    }

    public static AgentUpdateSignal FromHeartbeat(HeartbeatResponse response)
    {
        var update = response.Update;
        if (update is null)
            return new AgentUpdateSignal(false, false, null, null, null);

        return new AgentUpdateSignal(
            Required: ReadBool(update, "required"),
            Recommended: ReadBool(update, "recommended"),
            ManifestUrl: ReadString(update, "manifest_url"),
            Reason: ReadString(update, "reason"),
            Channel: ReadString(update, "channel"));
    }

    public async Task<AgentUpdateCheckResult> CheckAsync(HeartbeatResponse response, CancellationToken ct)
        => await CheckAsync(FromHeartbeat(response), ct).ConfigureAwait(false);

    public async Task<AgentUpdateCheckResult> CheckAsync(AgentUpdateSignal signal, CancellationToken ct)
    {
        if (!signal.Required && !signal.Recommended)
            return AgentUpdateCheckResult.None;

        var (manifest, _) = await LoadAndValidateManifestAsync(signal, ct).ConfigureAwait(false);
        if (!IsActionableManifest(manifest))
        {
            _log.Info($"Agent update skipped: target version {manifest.Version} is not newer than current version {_trust.CurrentVersion}.");
            return new AgentUpdateCheckResult(
                Available: false,
                Required: signal.Required,
                Recommended: signal.Recommended,
                Version: manifest.Version,
                Channel: manifest.Channel,
                Reason: "not_newer_than_current",
                ManifestUrl: signal.ManifestUrl,
                ArtifactKind: manifest.ArtifactKind);
        }

        return new AgentUpdateCheckResult(
            Available: true,
            Required: signal.Required,
            Recommended: signal.Recommended,
            Version: manifest.Version,
            Channel: manifest.Channel,
            Reason: signal.Reason,
            ManifestUrl: signal.ManifestUrl,
            ArtifactKind: manifest.ArtifactKind);
    }

    public async Task<AgentUpdatePlan?> StageAsync(HeartbeatResponse response, CancellationToken ct)
        => await StageAsync(FromHeartbeat(response), ct).ConfigureAwait(false);

    public async Task<AgentUpdatePlan?> StageAsync(AgentUpdateSignal signal, CancellationToken ct)
    {
        if (_trust.RequireSystemAuthority && !AgentUpdateSecurity.IsLocalSystem())
            throw new InvalidOperationException("Only the installed agent service may stage updates.");
        if (!signal.Required && !signal.Recommended)
            return null;

        AgentUpdateSecurity.EnsureProtectedRoot(_stagingRoot);
        var (manifest, manifestJson) = await LoadAndValidateManifestAsync(signal, ct).ConfigureAwait(false);
        if (!IsActionableManifest(manifest))
        {
            _log.Info($"Agent update staging skipped: target version {manifest.Version} is not newer than current version {_trust.CurrentVersion}.");
            return null;
        }

        using var operationLock = AgentUpdateSecurity.AcquireGlobalLock(_stagingRoot);
        var existing = FindExistingAttempt(manifest);
        if (existing is not null)
            return existing;

        if (manifest.IsV2 && AgentUpdateSequenceStore.HasAcceptedSequence(_stagingRoot, manifest.Sequence))
            throw new InvalidOperationException("Update manifest sequence was already accepted.");

        var attemptId = Guid.NewGuid().ToString("N");
        var attemptDir = AgentUpdateSecurity.CreateExclusiveAttemptDirectory(_stagingRoot, attemptId);
        var artifactPath = Path.Combine(attemptDir, AgentUpdateSecurity.ArtifactFileName);
        var partialPath = artifactPath + ".part";
        try
        {
            await DownloadWithHashCheckAsync(manifest, partialPath, ct).ConfigureAwait(false);
            AgentUpdateSecurity.ValidateTrustedPath(partialPath, _stagingRoot, allowMissing: false);
            AgentUpdateSecurity.ValidateTrustedPath(artifactPath, _stagingRoot, allowMissing: true);
            File.Move(partialPath, artifactPath, overwrite: false);
            AgentUpdateSecurity.ValidateTrustedPath(artifactPath, _stagingRoot, allowMissing: false);

            var artifactLength = new FileInfo(artifactPath).Length;
            var hash = await HashFileAsync(artifactPath, ct).ConfigureAwait(false);
            if (!string.Equals(hash, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Staged update checksum mismatch.");
            if (manifest.ArtifactLength is not null && manifest.ArtifactLength.Value != artifactLength)
                throw new InvalidOperationException("Staged update length mismatch.");

            var manifestPath = Path.Combine(attemptDir, AgentUpdateSecurity.ManifestFileName);
            var planPath = Path.Combine(attemptDir, AgentUpdateSecurity.PlanFileName);
            await WriteAtomicAsync(manifestPath, manifestJson, ct).ConfigureAwait(false);
            var plan = new AgentUpdatePlan(
                ArtifactKind: manifest.ArtifactKind,
                Version: manifest.Version,
                Channel: manifest.Channel,
                ArtifactPath: artifactPath,
                Sha256: manifest.Sha256.ToLowerInvariant(),
                StagedAtUtc: DateTimeOffset.UtcNow.ToString("O"),
                Reason: signal.Reason ?? "server_update_policy",
                AttemptId: attemptId,
                Sequence: manifest.Sequence,
                ExpiresAtUtc: manifest.ExpiresAtUtc,
                ArtifactLength: artifactLength,
                ManifestPath: manifestPath,
                SignerKeyIdentity: manifest.EffectiveSignerKeyIdentity,
                Required: signal.Required,
                RollbackAllowed: manifest.RollbackAllowed);
            await WriteAtomicAsync(planPath, JsonSerializer.Serialize(plan, JsonOptions), ct).ConfigureAwait(false);

            if (manifest.IsV2)
                AgentUpdateSequenceStore.Advance(_stagingRoot, manifest.Sequence);
            return plan;
        }
        catch
        {
            TryDeleteDirectory(attemptDir);
            throw;
        }
    }

    private async Task<(AgentUpdateManifest Manifest, string Json)> LoadAndValidateManifestAsync(
        AgentUpdateSignal signal,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(signal.ManifestUrl))
            throw new InvalidOperationException("Update requested but manifest URL is missing.");
        if (!Uri.TryCreate(signal.ManifestUrl, UriKind.Absolute, out var manifestUri) ||
            !string.Equals(manifestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update manifest URL must use HTTPS.");
        if (!string.IsNullOrWhiteSpace(signal.Channel) &&
            !string.Equals(signal.Channel, _trust.ExpectedChannel, StringComparison.Ordinal))
            throw new InvalidOperationException("Update signal channel mismatch.");
        if (!string.IsNullOrWhiteSpace(_trust.ConfiguredManifestUrl) &&
            !string.Equals(signal.ManifestUrl, _trust.ConfiguredManifestUrl, StringComparison.Ordinal))
            throw new InvalidOperationException("Update manifest URL is not trusted by this build.");

        string manifestJson;
        try
        {
            using var manifestResponse = await _http.GetAsync(signal.ManifestUrl, ct).ConfigureAwait(false);
            manifestResponse.EnsureSuccessStatusCode();
            manifestJson = await manifestResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            throw new InvalidOperationException("Update manifest unavailable.", ex);
        }

        var manifest = AgentUpdateManifestValidator.ParseAndValidateJson(
            manifestJson,
            _trust.ManifestPublicKeyPems,
            _trust.ExpectedChannel,
            _trust.AllowedArtifactPrefixes,
            currentVersion: _trust.CurrentVersion,
            allowRollbackManifest: _trust.AllowRollbackManifest,
            allowChannelDowngrade: _trust.AllowChannelDowngrade);
        if (_trust.RequireManifestV2 && !manifest.IsV2)
            throw new InvalidOperationException("Update manifest v2 is required for this release channel.");
        if (!manifest.IsV2 && AgentUpdateSequenceStore.ReadHighest(_stagingRoot) > 0)
            throw new InvalidOperationException("Legacy update manifest fallback is disabled after v2 trust was accepted.");
        ValidateSignerIdentity(manifest);
        return (manifest, manifestJson);
    }

    private void ValidateSignerIdentity(AgentUpdateManifest manifest)
    {
        var expected = _trust.AllowedSignerKeyIdentity?.Trim();
        var actual = manifest.EffectiveSignerKeyIdentity;
        if (string.IsNullOrWhiteSpace(expected))
        {
            if (!string.IsNullOrWhiteSpace(actual))
                throw new InvalidOperationException("Update manifest signer identity is not embedded in this build.");
            return;
        }

        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update manifest signer identity does not match this build.");
    }

    private bool IsActionableManifest(AgentUpdateManifest manifest)
    {
        var compare = AgentVersionComparer.CompareReleaseCore(manifest.Version, _trust.CurrentVersion);
        if (compare is null)
            return true;
        if (compare > 0)
            return true;
        return compare < 0 &&
               (_trust.AllowChannelDowngrade || (_trust.AllowRollbackManifest && manifest.RollbackAllowed));
    }

    private AgentUpdatePlan? FindExistingAttempt(AgentUpdateManifest manifest)
    {
        var attemptsRoot = Path.Combine(_stagingRoot, "attempts");
        if (!Directory.Exists(attemptsRoot))
            return null;

        foreach (var directory in Directory.EnumerateDirectories(attemptsRoot, AgentUpdateSecurity.AttemptDirectoryPrefix + "*"))
        {
            try
            {
                AgentUpdateSecurity.ValidateTrustedPath(directory, attemptsRoot, allowMissing: false);
                var planPath = Path.Combine(directory, AgentUpdateSecurity.PlanFileName);
                if (!File.Exists(planPath))
                    continue;
                var plan = JsonSerializer.Deserialize<AgentUpdatePlan>(File.ReadAllText(planPath), JsonOptions);
                if (plan is not null &&
                    string.Equals(plan.Version, manifest.Version, StringComparison.Ordinal) &&
                    string.Equals(plan.Channel, manifest.Channel, StringComparison.Ordinal) &&
                    string.Equals(plan.Sha256, manifest.Sha256, StringComparison.OrdinalIgnoreCase) &&
                    plan.Sequence == manifest.Sequence &&
                    string.Equals(plan.ExpiresAtUtc, manifest.ExpiresAtUtc, StringComparison.Ordinal) &&
                    string.Equals(plan.SignerKeyIdentity, manifest.EffectiveSignerKeyIdentity, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(plan.AttemptId))
                    return plan;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
            {
            }
        }

        return null;
    }

    private async Task DownloadWithHashCheckAsync(
        AgentUpdateManifest manifest,
        string artifactPath,
        CancellationToken ct)
    {
        AgentUpdateSecurity.ValidateTrustedPath(artifactPath, _stagingRoot, allowMissing: true);
        if (_trust.RequireBitsDownloader)
        {
            await new AgentUpdateBitsDownloader()
                .DownloadAsync(
                    new Uri(manifest.ArtifactUrl, UriKind.Absolute),
                    artifactPath,
                    _trust.MaxArtifactBytes,
                    ct)
                .ConfigureAwait(false);
            return;
        }

        HttpResponseMessage response;
        try
        {
            response = await _http.GetAsync(
                manifest.ArtifactUrl,
                HttpCompletionOption.ResponseHeadersRead,
                ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            throw new InvalidOperationException("Update artifact download failed.", ex);
        }

        using (response)
        {
            if (response.Content.Headers.ContentLength is > 0 &&
                response.Content.Headers.ContentLength > _trust.MaxArtifactBytes)
                throw new InvalidOperationException("Update artifact exceeds size limit.");

            try
            {
                await using var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                await using var target = new FileStream(artifactPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                using var sha = SHA256.Create();
                var buffer = new byte[64 * 1024];
                long total = 0;
                long nextProgressBytes = 8 * 1024 * 1024;
                var contentLength = response.Content.Headers.ContentLength;
                while (true)
                {
                    var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                    if (read <= 0)
                        break;
                    total += read;
                    if (total > _trust.MaxArtifactBytes)
                        throw new InvalidOperationException("Update artifact exceeds size limit.");
                    await target.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                    sha.TransformBlock(buffer, 0, read, null, 0);
                    if (total >= nextProgressBytes)
                    {
                        LogDownloadProgress(total, contentLength);
                        nextProgressBytes = total + (8 * 1024 * 1024);
                    }
                }

                LogDownloadProgress(total, contentLength);
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                var hash = Convert.ToHexString(sha.Hash ?? Array.Empty<byte>()).ToLowerInvariant();
                if (!string.Equals(hash, manifest.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Update artifact checksum mismatch.");
                if (manifest.ArtifactLength is not null && manifest.ArtifactLength.Value != total)
                    throw new InvalidOperationException("Update artifact length mismatch.");
            }
            catch
            {
                TryDeleteFile(artifactPath);
                throw;
            }
        }
    }

    private void LogDownloadProgress(long total, long? contentLength)
    {
        if (contentLength is > 0)
        {
            var pct = Math.Min(100, (double)total / contentLength.Value * 100);
            _log.Info($"Agent update download progress: {total}/{contentLength.Value} bytes ({pct:F1}%).");
            return;
        }

        _log.Info($"Agent update download progress: {total} bytes.");
    }

    [Obsolete("Direct plan application is disabled; only the SYSTEM updater may apply an attempt.")]
    public static Task ApplyPlanAsync(string planPath, string targetExecutablePath, CancellationToken ct)
        => throw new InvalidOperationException("Direct update application is disabled.");

    [Obsolete("Direct plan application is disabled; only the SYSTEM updater may apply an attempt.")]
    public static Task ApplyPlanAsync(
        string planPath,
        string targetExecutablePath,
        string trustedStagingRoot,
        string allowedTargetExecutablePath,
        CancellationToken ct)
        => throw new InvalidOperationException("Direct update application is disabled.");

    private static async Task<string> HashFileAsync(string path, CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private async Task WriteAtomicAsync(string path, string contents, CancellationToken ct)
    {
        AgentUpdateSecurity.ValidateTrustedPath(path, _stagingRoot, allowMissing: true);
        var tempPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            AgentUpdateSecurity.ValidateTrustedPath(tempPath, _stagingRoot, allowMissing: true);
            await File.WriteAllTextAsync(tempPath, contents, ct).ConfigureAwait(false);
            File.Move(tempPath, path, overwrite: false);
        }
        finally
        {
            TryDeleteFile(tempPath);
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static bool ReadBool(IReadOnlyDictionary<string, JsonElement> values, string key)
    {
        if (!values.TryGetValue(key, out var value))
            return false;
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.String => bool.TryParse(value.GetString(), out var parsed) && parsed,
            _ => false,
        };
    }

    private static string? ReadString(IReadOnlyDictionary<string, JsonElement> values, string key)
        => values.TryGetValue(key, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
