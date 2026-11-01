using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App;

internal static partial class ServiceMode
{
    internal static async Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl,
        string? TailscaleLoginServer, string? TailscaleAuthkey)?> LoadServiceCredentialsAsync(
        ISecretStore secrets, IAgentLifecycleStateStore lifecycle, IAgentLogger log, CancellationToken ct)
    {
        try { return await secrets.LoadAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or CryptographicException or
            InvalidOperationException or JsonException)
        {
            var (reason, message) = ex switch
            {
                FileNotFoundException or DirectoryNotFoundException => ("credentials_missing", "machine credentials are not enrolled"),
                CryptographicException => ("credentials_unavailable", "machine credentials are unavailable"),
                JsonException => ("credentials_invalid", "machine credentials are malformed"),
                _ => ("credentials_invalid", "machine credentials could not be decoded"),
            };
            await lifecycle.TransitionAsync(AgentLifecycleState.NeedsReenrollment, reason, null, null, null, ct).ConfigureAwait(false);
            log.Warn($"Service starting dormant; {message}.");
            return null;
        }
        // Transient IO/access failures propagate to the worker supervisor. They do not retire
        // an otherwise valid registration, and the next worker retries with the existing backoff.
    }
}
