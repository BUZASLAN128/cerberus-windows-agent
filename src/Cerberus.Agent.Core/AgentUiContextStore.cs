using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Core;

public sealed record AgentUiContext(
    string AgentId,
    string TenantId,
    string? TenantName,
    string? AccountLabel,
    string UpdatedAtUtc);

public static class AgentUiContextStore
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static Task WriteBestEffortAsync(
        AgentIdentity identity,
        string? tenantName,
        string? accountLabel,
        CancellationToken ct)
        => WriteBestEffortAsync(identity, tenantName, accountLabel, ct, CandidatePaths().First(), CandidatePaths().Last());

    internal static async Task WriteBestEffortAsync(
        AgentIdentity identity,
        string? tenantName,
        string? accountLabel,
        CancellationToken ct,
        string userPath,
        string machinePath)
    {
        var context = new AgentUiContext(
            identity.AgentId,
            identity.TenantId,
            NormalizeOptional(tenantName),
            NormalizeOptional(accountLabel),
            DateTimeOffset.UtcNow.ToString("O"));

        foreach (var (path, createDirectory) in new[] { (userPath, true), (machinePath, false) })
        {
            try
            {
                ct.ThrowIfCancellationRequested();
                var directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    // Only elevated installer/service provisioning may create the machine namespace.
                    if (createDirectory) Directory.CreateDirectory(directory);
                    else if (!Directory.Exists(directory)) continue;
                }
                await File.WriteAllTextAsync(
                    path,
                    JsonSerializer.Serialize(context, JsonOpts),
                    System.Text.Encoding.UTF8,
                    ct).ConfigureAwait(false);
            }
            catch
            {
                // Non-secret UI context must never block registration or heartbeat handling.
            }
        }
    }

    public static AgentUiContext? ReadBestEffort()
    {
        foreach (var path in CandidatePaths())
        {
            try
            {
                if (!File.Exists(path))
                    continue;

                var raw = File.ReadAllText(path, System.Text.Encoding.UTF8);
                var context = JsonSerializer.Deserialize<AgentUiContext>(raw, JsonOpts);
                if (!string.IsNullOrWhiteSpace(context?.AgentId) &&
                    !string.IsNullOrWhiteSpace(context.TenantId))
                {
                    return context;
                }
            }
            catch
            {
                // Ignore corrupt or inaccessible UI context and try the next scope.
            }
        }
        return null;
    }

    public static string DisplayTenant(AgentUiContext? context)
    {
        var tenantName = NormalizeOptional(context?.TenantName);
        if (!string.IsNullOrWhiteSpace(tenantName))
            return tenantName;

        return ShortId(context?.TenantId);
    }

    public static string DisplayAccount(AgentUiContext? context)
    {
        var account = NormalizeOptional(context?.AccountLabel);
        if (!string.IsNullOrWhiteSpace(account))
            return account;

        var agent = ShortId(context?.AgentId);
        return agent == "-" ? "-" : $"agent {agent}";
    }

    private static IEnumerable<string> CandidatePaths()
    {
        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CerberusAgent",
            "ui-context.json");
        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CerberusAgent",
            "ui-context.json");
    }

    private static string ShortId(string? value)
    {
        var normalized = NormalizeOptional(value);
        if (string.IsNullOrWhiteSpace(normalized))
            return "-";
        return normalized.Length <= 8 ? normalized : normalized[..8];
    }

    private static string? NormalizeOptional(string? value)
    {
        var normalized = String(value);
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }

    private static string? String(string? value)
        => value?.Trim();
}
