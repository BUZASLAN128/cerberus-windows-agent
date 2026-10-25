using System.Text;

namespace Cerberus.Agent.Core;

/// <summary>
/// Ack and result calls for signed command envelopes. The body is sent exactly as
/// given: the caller stores these bytes and re-sends them unchanged.
/// </summary>
public sealed partial class AgentApiClient
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>POST /api/v1/agents/{agent_id}/commands/{id}/ack with the exact body bytes.</summary>
    public Task SubmitEnvelopeAckAsync(string agentId, string commandId, byte[] body, CancellationToken ct)
        => PostEnvelopeBytesAsync("ack", "Command acknowledgement", agentId, commandId, body, ct);

    /// <summary>POST /api/v1/agents/{agent_id}/commands/{id}/result with the exact stored body bytes.</summary>
    public Task SubmitEnvelopeResultAsync(string agentId, string commandId, byte[] body, CancellationToken ct)
        => PostEnvelopeBytesAsync("result", "Command result", agentId, commandId, body, ct);

    private async Task PostEnvelopeBytesAsync(
        string leaf,
        string operation,
        string agentId,
        string commandId,
        byte[] body,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(body);
        var json = StrictUtf8.GetString(body);
        if (!StrictUtf8.GetBytes(json).AsSpan().SequenceEqual(body))
            throw new InvalidOperationException("Envelope body does not round-trip as UTF-8.");

        await EnsureAutomaticNetworkAllowedAsync(ct).ConfigureAwait(false);
        var (identity, _, _, _, _, _) = await _secrets.LoadAsync(ct).ConfigureAwait(false);
        // The path comes from the current credential; never post one agent's record under another.
        if (!string.Equals(identity.AgentId, agentId, StringComparison.Ordinal))
            throw new InvalidOperationException("Envelope record belongs to a different agent id.");

        var path = $"/api/v1/agents/{Uri.EscapeDataString(identity.AgentId)}/commands/" +
                   $"{Uri.EscapeDataString(commandId)}/{leaf}";
        using var response = await SendSignedJsonRequestAsync(
            HttpMethod.Post,
            path,
            json,
            ct,
            HttpCompletionOption.ResponseHeadersRead,
            resourceOperation: true).ConfigureAwait(false);
        await EnsureSuccessAsync(operation, response, ct, resourceOperation: true).ConfigureAwait(false);
    }
}
