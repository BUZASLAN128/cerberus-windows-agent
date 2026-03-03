using System.Diagnostics;
using System.Text.Json;

namespace Cerberus.Agent.Integrations.Tailscale;

public static class TailscaleStatusProbe
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public static async Task<(bool Installed, bool Connected, object? Snapshot, string? Error)> ProbeAsync(
        TimeSpan timeout,
        CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "tailscale",
                Arguments = "status --json",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var p = Process.Start(psi);
            if (p is null)
                return (Installed: false, Connected: false, Snapshot: null, Error: "tailscale process failed to start.");

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
                return (Installed: true, Connected: false, Snapshot: null, Error: string.IsNullOrWhiteSpace(stderr) ? stdout : stderr);
            }

            if (string.IsNullOrWhiteSpace(stdout))
                return (Installed: true, Connected: false, Snapshot: null, Error: "tailscale status returned empty output.");

            using var doc = JsonDocument.Parse(stdout);
            var root = doc.RootElement;

            // Best-effort: treat state=Running as "connected enough" for legacy tests.
            var connected = false;
            if (root.TryGetProperty("BackendState", out var stateProp))
            {
                var state = stateProp.GetString();
                connected = string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase);
            }

            var snapshot = JsonSerializer.Deserialize<object>(stdout, JsonOpts);
            return (Installed: true, Connected: connected, Snapshot: snapshot, Error: null);
        }
        catch (FileNotFoundException)
        {
            return (Installed: false, Connected: false, Snapshot: null, Error: "tailscale executable not found.");
        }
        catch (OperationCanceledException)
        {
            return (Installed: true, Connected: false, Snapshot: null, Error: "tailscale status timed out.");
        }
        catch (Exception ex)
        {
            return (Installed: true, Connected: false, Snapshot: null, Error: $"{ex.GetType().Name}: {ex.Message}");
        }
    }
}

