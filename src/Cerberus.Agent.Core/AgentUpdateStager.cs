using System.Security.Cryptography;
using System.Text.Json;

namespace Cerberus.Agent.Core;

public sealed record AgentUpdateTrust(
    string ManifestPublicKeyPem,
    string ExpectedChannel,
    IReadOnlyList<string> AllowedArtifactPrefixes,
    string CurrentVersion,
    bool AllowRollbackManifest = false,
    long MaxArtifactBytes = 200 * 1024 * 1024);

public sealed record AgentUpdateSignal(
    bool Required,
    bool Recommended,
    string? ManifestUrl,
    string? Reason,
    string? Channel);

public sealed record AgentUpdatePlan(
    string Version,
    string Channel,
    string ArtifactPath,
    string Sha256,
    string StagedAtUtc,
    string Reason);

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

    public static string DefaultStagingRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CerberusAgent",
        "updates");

    public AgentUpdateStager(HttpClient http, AgentUpdateTrust trust, string stagingRoot, IAgentLogger? log = null)
    {
        _http = http;
        _trust = trust;
        _stagingRoot = string.IsNullOrWhiteSpace(stagingRoot)
            ? throw new ArgumentException("Update staging root is required.", nameof(stagingRoot))
            : stagingRoot;
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

    public async Task<AgentUpdatePlan?> StageAsync(HeartbeatResponse response, CancellationToken ct)
    {
        var signal = FromHeartbeat(response);
        if (!signal.Required && !signal.Recommended)
            return null;
        if (string.IsNullOrWhiteSpace(signal.ManifestUrl))
            throw new InvalidOperationException("Update requested but manifest URL is missing.");
        if (!string.IsNullOrWhiteSpace(signal.Channel) &&
            !string.Equals(signal.Channel, _trust.ExpectedChannel, StringComparison.Ordinal))
            throw new InvalidOperationException("Update signal channel mismatch.");

        using var manifestResponse = await _http.GetAsync(signal.ManifestUrl, ct).ConfigureAwait(false);
        manifestResponse.EnsureSuccessStatusCode();
        var manifestJson = await manifestResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var manifest = AgentUpdateManifestValidator.ParseAndValidateJson(
            manifestJson,
            _trust.ManifestPublicKeyPem,
            _trust.ExpectedChannel,
            _trust.AllowedArtifactPrefixes,
            currentVersion: _trust.CurrentVersion,
            allowRollbackManifest: _trust.AllowRollbackManifest);

        var stageDir = Path.Combine(_stagingRoot, manifest.Version);
        Directory.CreateDirectory(stageDir);
        var artifactName = Path.GetFileName(new Uri(manifest.ArtifactUrl).LocalPath);
        if (string.IsNullOrWhiteSpace(artifactName))
            artifactName = $"Cerberus.Agent.App-{manifest.Version}.exe";
        var artifactPath = Path.Combine(stageDir, artifactName);

        await DownloadWithHashCheckAsync(manifest, artifactPath, ct).ConfigureAwait(false);

        var plan = new AgentUpdatePlan(
            Version: manifest.Version,
            Channel: manifest.Channel,
            ArtifactPath: artifactPath,
            Sha256: manifest.Sha256.ToLowerInvariant(),
            StagedAtUtc: DateTimeOffset.UtcNow.ToString("O"),
            Reason: signal.Reason ?? "server_update_policy");
        await File.WriteAllTextAsync(
            Path.Combine(stageDir, "update-plan.json"),
            JsonSerializer.Serialize(plan, JsonOptions),
            ct).ConfigureAwait(false);
        PruneOldStagedVersions(manifest.Version);
        return plan;
    }

    public static Task ApplyPlanAsync(string planPath, string targetExecutablePath, CancellationToken ct)
    {
        var stagingRoot = Path.GetDirectoryName(Path.GetFullPath(planPath))
            ?? throw new InvalidOperationException("Update plan directory could not be resolved.");
        return ApplyPlanAsync(planPath, targetExecutablePath, stagingRoot, targetExecutablePath, ct);
    }

    public static async Task ApplyPlanAsync(
        string planPath,
        string targetExecutablePath,
        string trustedStagingRoot,
        string allowedTargetExecutablePath,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(planPath))
            throw new ArgumentException("Update plan path is required.", nameof(planPath));
        if (string.IsNullOrWhiteSpace(targetExecutablePath))
            throw new ArgumentException("Target executable path is required.", nameof(targetExecutablePath));
        if (string.IsNullOrWhiteSpace(trustedStagingRoot))
            throw new ArgumentException("Trusted staging root is required.", nameof(trustedStagingRoot));
        if (string.IsNullOrWhiteSpace(allowedTargetExecutablePath))
            throw new ArgumentException("Allowed target executable path is required.", nameof(allowedTargetExecutablePath));

        var fullPlanPath = Path.GetFullPath(planPath);
        var fullStagingRoot = Path.GetFullPath(trustedStagingRoot);
        var fullTargetPath = Path.GetFullPath(targetExecutablePath);
        var fullAllowedTargetPath = Path.GetFullPath(allowedTargetExecutablePath);
        if (!IsUnderDirectory(fullPlanPath, fullStagingRoot))
            throw new InvalidOperationException("Update plan path is outside trusted staging root.");
        if (!string.Equals(fullTargetPath, fullAllowedTargetPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update target executable path is not allowed.");

        var raw = await File.ReadAllTextAsync(fullPlanPath, ct).ConfigureAwait(false);
        var plan = JsonSerializer.Deserialize<AgentUpdatePlan>(raw, JsonOptions)
            ?? throw new InvalidOperationException("Update plan is invalid.");
        if (!File.Exists(plan.ArtifactPath))
            throw new FileNotFoundException("Staged update artifact not found.", plan.ArtifactPath);
        var fullArtifactPath = Path.GetFullPath(plan.ArtifactPath);
        if (!IsUnderDirectory(fullArtifactPath, fullStagingRoot))
            throw new InvalidOperationException("Update artifact path is outside trusted staging root.");

        var hash = await HashFileAsync(fullArtifactPath, ct).ConfigureAwait(false);
        if (!string.Equals(hash, plan.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Staged update checksum mismatch.");

        var targetDir = Path.GetDirectoryName(fullTargetPath);
        if (!string.IsNullOrWhiteSpace(targetDir))
            Directory.CreateDirectory(targetDir);
        var backupPath = File.Exists(fullTargetPath)
            ? $"{fullTargetPath}.bak-{Guid.NewGuid():N}"
            : null;
        try
        {
            if (backupPath is not null)
                File.Move(fullTargetPath, backupPath, overwrite: false);

            File.Copy(fullArtifactPath, fullTargetPath, overwrite: false);
            var appliedHash = await HashFileAsync(fullTargetPath, ct).ConfigureAwait(false);
            if (!string.Equals(appliedHash, plan.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Applied update checksum mismatch.");

            if (backupPath is not null && File.Exists(backupPath))
                File.Delete(backupPath);
        }
        catch
        {
            if (backupPath is not null && File.Exists(backupPath))
            {
                if (File.Exists(fullTargetPath))
                    File.Delete(fullTargetPath);
                File.Move(backupPath, fullTargetPath, overwrite: false);
            }
            throw;
        }
    }

    private async Task DownloadWithHashCheckAsync(
        AgentUpdateManifest manifest,
        string artifactPath,
        CancellationToken ct)
    {
        using var response = await _http.GetAsync(
            manifest.ArtifactUrl,
            HttpCompletionOption.ResponseHeadersRead,
            ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is > 0 &&
            response.Content.Headers.ContentLength > _trust.MaxArtifactBytes)
            throw new InvalidOperationException("Update artifact exceeds size limit.");

        await using var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await using var target = File.Create(artifactPath);
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

    private void PruneOldStagedVersions(string currentVersion)
    {
        try
        {
            var root = new DirectoryInfo(_stagingRoot);
            if (!root.Exists)
                return;

            var oldDirs = root
                .EnumerateDirectories()
                .Where(dir => !string.Equals(dir.Name, currentVersion, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(dir => dir.CreationTimeUtc)
                .Skip(2)
                .ToArray();

            foreach (var dir in oldDirs)
                dir.Delete(recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Warn($"Agent update staging cleanup skipped: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static async Task<string> HashFileAsync(string path, CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool IsUnderDirectory(string path, string directory)
    {
        var normalizedDirectory = directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return path.StartsWith(normalizedDirectory, StringComparison.OrdinalIgnoreCase);
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
    {
        if (!values.TryGetValue(key, out var value))
            return null;
        return value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }
}
