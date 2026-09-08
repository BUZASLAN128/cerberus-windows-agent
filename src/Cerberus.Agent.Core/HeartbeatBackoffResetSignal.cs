namespace Cerberus.Agent.Core;

public static class HeartbeatBackoffResetSignal
{
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CerberusAgent",
        "heartbeat-backoff-reset.signal");

    public static bool TryRequest(string reason)
        => TryRequest(DefaultPath, reason);

    public static bool TryRequest(string path, string reason)
    {
        try
        {
            var directory = Path.GetDirectoryName(path);
            // A pre-service UI request must not claim ownership of the machine namespace.
            if (!string.IsNullOrWhiteSpace(directory) && !Directory.Exists(directory))
                return false;

            File.WriteAllText(path, $"{DateTimeOffset.UtcNow:O}\n{reason}\n");
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static Task<bool> ConsumeDefaultAsync(CancellationToken ct)
        => ConsumeAsync(DefaultPath, ct);

    public static Task<bool> ConsumeAsync(string path, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!File.Exists(path))
            return Task.FromResult(false);

        try
        {
            File.Delete(path);
            return Task.FromResult(true);
        }
        catch (FileNotFoundException)
        {
            return Task.FromResult(false);
        }
        catch (DirectoryNotFoundException)
        {
            return Task.FromResult(false);
        }
        catch
        {
            return Task.FromResult(false);
        }
    }
}
