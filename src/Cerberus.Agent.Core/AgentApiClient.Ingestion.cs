using System.Net;
using System.Text.Json;

namespace Cerberus.Agent.Core;

public sealed partial class AgentApiClient
{
    private async Task<AgentIngestAckResponse> SubmitIngestAsync(
        string endpoint,
        object body,
        bool retryTransient,
        CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(body, JsonOpts);
        return await SubmitIngestJsonAsync(endpoint, json, retryTransient, ct).ConfigureAwait(false);
    }

    private async Task<AgentIngestAckResponse> SubmitIngestJsonAsync(
        string endpoint,
        string json,
        bool retryTransient,
        CancellationToken ct,
        Func<string>? jsonFactory = null)
    {
        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        AgentTelemetryLimits.ThrowIfJsonTooLarge(json,
            endpoint == "snapshot" ? SnapshotByteLimit : AgentTelemetryLimits.MaxJsonBytes);
        var (id, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        var path = $"/api/v1/agents/{id.AgentId}/{endpoint}";

        async Task<AgentIngestAckResponse> SubmitOnceAsync()
        {
            using var resp = await SendSignedJsonRequestAsync(
                HttpMethod.Post,
                path,
                json,
                ct,
                HttpCompletionOption.ResponseHeadersRead, jsonFactory: jsonFactory).ConfigureAwait(false);
            if (endpoint == "snapshot" && resp.StatusCode == HttpStatusCode.RequestEntityTooLarge)
            {
                _snapshotRejectedAsTooLarge = true;
                _snapshotByteLimit = Math.Min(SnapshotByteLimit, AgentTelemetryLimits.MaxJsonBytes);
            }
            if (endpoint == "snapshot" && resp.StatusCode == HttpStatusCode.UnprocessableEntity)
            {
                _snapshotSectionsRejected = true;
                _snapshotSections = AgentSnapshotFactory.SnapshotSectionsFor(null, _secondarySnapshot);
            }
            await EnsureSuccessAsync($"Agent {endpoint}", resp, ct).ConfigureAwait(false);

            var payload = await AgentHttpFailure.ReadJsonAsync<AgentIngestAckResponse>(
                $"Agent {endpoint}",
                resp,
                _http,
                JsonOpts,
                ct).ConfigureAwait(false);
            return payload ?? throw new InvalidOperationException("Agent ingestion response missing.");
        }

        return retryTransient
            ? await RetryHelper.WithRetryAsync(SubmitOnceAsync, maxRetries: 1, ct: ct).ConfigureAwait(false)
            : await SubmitOnceAsync().ConfigureAwait(false);
    }

}
