using System.IO;
using System.IO.Compression;
using System.Text.Json;
using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Diagnostics;

internal static class AgentDiagnosticsBundle
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<string> ExportAsync(string? outputDir = null, string? logDir = null, CancellationToken ct = default)
    {
        outputDir ??= Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CerberusAgent",
            "diagnostics");
        Directory.CreateDirectory(outputDir);

        var path = Path.Combine(outputDir, $"cerberus-agent-diagnostics-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}.zip");
        if (File.Exists(path))
            File.Delete(path);

        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        await WriteTextEntryAsync(archive, "summary.json", await BuildSummaryAsync(ct), ct);
        await CopyRecentLogsAsync(archive, logDir, ct);
        return path;
    }

    internal static string Redact(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "";

        var redacted = Sanitizer.Redact(value);
        foreach (var marker in new[] { "token", "secret", "private_key", "refresh_token", "client_secret", "password" })
        {
            redacted = System.Text.RegularExpressions.Regex.Replace(
                redacted,
                $"(?i)(\"?{marker}\"?\\s*[:=]\\s*)\"?[^\r\n,}}]+\"?",
                "$1[REDACTED]");
        }

        return redacted;
    }

    private static async Task<string> BuildSummaryAsync(CancellationToken ct)
    {
        var service = AgentStatus.GetService();
        var registered = AgentStatus.IsRegistered();
        var tailscale = await AgentStatus.GetTailscaleAsync(ct);
        var installRoot = AppContext.BaseDirectory;
        var userSecretPath = DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.User);
        var machineSecretPath = DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.Machine);

        var payload = new
        {
            generated_at_utc = DateTimeOffset.UtcNow,
            product = "Cerberus Windows Agent",
            version = typeof(AgentDiagnosticsBundle).Assembly.GetName().Version?.ToString() ?? "unknown",
            install_root = installRoot,
            service = new { service.Text, service.Short, service.Installed },
            registered,
            connector = tailscale.Text,
            secrets = new
            {
                user_scope_present = File.Exists(userSecretPath),
                machine_scope_present = File.Exists(machineSecretPath),
            },
        };

        return Redact(JsonSerializer.Serialize(payload, JsonOpts));
    }

    private static async Task CopyRecentLogsAsync(ZipArchive archive, string? logDir, CancellationToken ct)
    {
        var logDirectories = logDir is null
            ? new[] { AgentFileLogger.UserLogDirectory, AgentFileLogger.ServiceLogDirectory }
            : new[] { logDir! };

        foreach (var directory in logDirectories.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(directory))
                continue;

            string[] files;
            try
            {
                files = Directory
                    .EnumerateFiles(directory, "*.log", SearchOption.TopDirectoryOnly)
                    .OrderByDescending(File.GetLastWriteTimeUtc)
                    .Take(3)
                    .ToArray();
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var text = await File.ReadAllTextAsync(file, ct);
                    await WriteTextEntryAsync(archive, $"logs/{Path.GetFileName(file)}", Redact(text), ct);
                }
                catch (IOException)
                {
                    // Diagnostics should continue if one log is locked.
                }
                catch (UnauthorizedAccessException)
                {
                    // Diagnostics should continue if one log is not readable by the current user.
                }
            }
        }
    }

    private static async Task WriteTextEntryAsync(ZipArchive archive, string entryName, string content, CancellationToken ct)
    {
        var entry = archive.CreateEntry(entryName, CompressionLevel.Optimal);
        await using var stream = entry.Open();
        await using var writer = new StreamWriter(stream);
        await writer.WriteAsync(content.AsMemory(), ct);
    }
}
