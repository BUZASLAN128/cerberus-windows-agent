using System.Diagnostics;
using System.Text.Json;

namespace Cerberus.Agent.Integrations.Tailscale;

public static class TailscaleStatusProbe
{
    public const string StatusArguments = "status --json";
    private static readonly object CacheGate = new();
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(5);
    private static DateTimeOffset _cachedAtUtc;
    private static (bool Installed, bool Connected, object? Snapshot, string? Error)? _cachedResult;

    public static ProcessStartInfo CreateStatusStartInfo() => new()
    {
        FileName = "tailscale",
        Arguments = StatusArguments,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };

    public static async Task<(bool Installed, bool Connected, object? Snapshot, string? Error)> ProbeAsync(
        TimeSpan timeout,
        CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        lock (CacheGate)
        {
            if (_cachedResult is not null && now - _cachedAtUtc <= CacheTtl)
                return _cachedResult.Value;
        }

        try
        {
            var psi = CreateStatusStartInfo();

            using var p = Process.Start(psi);
            if (p is null)
                return Cache((Installed: false, Connected: false, Snapshot: null, Error: "tailscale process failed to start."));

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            var stdoutTask = p.StandardOutput.ReadToEndAsync();
            var stderrTask = p.StandardError.ReadToEndAsync();

            await p.WaitForExitAsync(cts.Token);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (p.ExitCode != 0)
            {
                // If tailscale is installed but not ready/connected, it may still return non-zero.
                return Cache((Installed: true, Connected: false, Snapshot: null, Error: string.IsNullOrWhiteSpace(stderr) ? stdout : stderr));
            }

            if (string.IsNullOrWhiteSpace(stdout))
                return Cache((Installed: true, Connected: false, Snapshot: null, Error: "tailscale status returned empty output."));

            var (connected, snapshot) = ParseStatusSnapshot(stdout);
            return Cache((Installed: true, Connected: connected, Snapshot: snapshot, Error: null));
        }
        catch (FileNotFoundException)
        {
            return Cache((Installed: false, Connected: false, Snapshot: null, Error: "tailscale executable not found."));
        }
        catch (OperationCanceledException)
        {
            return Cache((Installed: true, Connected: false, Snapshot: null, Error: "tailscale status timed out."));
        }
        catch (Exception ex)
        {
            return Cache((Installed: true, Connected: false, Snapshot: null, Error: $"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    private static (bool Installed, bool Connected, object? Snapshot, string? Error) Cache(
        (bool Installed, bool Connected, object? Snapshot, string? Error) result)
    {
        lock (CacheGate)
        {
            _cachedAtUtc = DateTimeOffset.UtcNow;
            _cachedResult = result;
        }

        return result;
    }

    public static (bool Connected, object Snapshot) ParseStatusSnapshot(string stdout)
    {
        using var doc = JsonDocument.Parse(stdout);
        var root = doc.RootElement;

        string? state = null;
        if (root.TryGetProperty("BackendState", out var stateProp))
            state = stateProp.GetString();
        var connected = string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase);

        var selfIps = new List<string>();
        string? dnsName = null;
        bool? online = null;

        if (root.TryGetProperty("Self", out var self) && self.ValueKind == JsonValueKind.Object)
        {
            dnsName = ReadString(self, "DNSName");
            online = ReadBool(self, "Online");
            selfIps.AddRange(ReadStringArray(self, "TailscaleIPs"));
        }

        selfIps.AddRange(ReadStringArray(root, "TailscaleIPs"));

        var snapshot = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["state"] = state,
            ["ips"] = selfIps.Distinct(StringComparer.Ordinal).ToArray(),
            ["self"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["dns_name"] = dnsName,
                ["online"] = online,
            },
        };

        return (connected, snapshot);
    }

    private static string? ReadString(JsonElement parent, string name)
    {
        return parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
    }

    private static bool? ReadBool(JsonElement parent, string name)
    {
        return parent.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False
            ? value.GetBoolean()
            : null;
    }

    private static IReadOnlyList<string> ReadStringArray(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Array)
            return Array.Empty<string>();

        return value.EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString())
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Select(item => item!)
            .ToArray();
    }
}
