using System.Globalization;
using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

/// <summary>One wire-header implementation for refresh, API calls and wakeup handshakes.</summary>
public static class AgentRequestSigning
{
    public static void AddHeaders(HttpRequestMessage request, byte[] body, string agentId, Uri backend, IRequestSigner signer)
    {
        var target = new Uri(backend, request.RequestUri!);
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var bodyHash = signer.ComputeBodyHash(body);
        var canonical = signer.CanonicalString(request.Method.Method, target.AbsolutePath, nonce, timestamp, bodyHash);
        request.Headers.Add("X-Agent-Id", agentId);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-Timestamp", timestamp.ToString(CultureInfo.InvariantCulture));
        request.Headers.Add("X-Body-Hash", bodyHash);
        request.Headers.Add("X-Signature", signer.Sign(canonical));
        request.Headers.Add("X-Signature-V2", signer.Sign($"cerberus-agent-sig-v2\n{canonical}\n{target.Authority.ToLowerInvariant()}"));
    }
}
