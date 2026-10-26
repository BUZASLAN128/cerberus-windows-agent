using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Cerberus.Agent.Core;

/// <summary>Rejection codes of the signed command envelope (contract v1).</summary>
public static class EnvelopeCodes
{
    public const string Unsigned = "unsigned";
    public const string Malformed = "envelope_malformed";
    public const string DelegationUnsupported = "delegation_unsupported";
    public const string NoTrustAnchor = "no_trust_anchor";
    public const string KeyUnknown = "key_unknown";
    public const string SignatureInvalid = "signature_invalid";
    public const string AgentMismatch = "agent_mismatch";
    public const string Mismatch = "envelope_mismatch";
    public const string TypeNotAllowed = "type_not_allowed";
    public const string PayloadInvalid = "payload_invalid";
    public const string IdConflict = "id_conflict";
    public const string TtlInvalid = "ttl_invalid";
    public const string NotYetValid = "not_yet_valid";
    public const string Expired = "expired";
    public const string IssuedBeforeReset = "issued_before_reset";
    public const string NonceReused = "nonce_reused";
    public const string Quarantined = "quarantined";
    public const string ReplayStoreFull = "replay_store_full";
    public const string ReplayStoreUnavailable = "replay_store_unavailable";
}

/// <summary>Command types that may arrive inside an envelope.</summary>
public static class EnvelopeTypes
{
    public const string Ping = "ping";
    public const string CollectFacts = "collect_facts";
    public const string AgentState = "agent_state";

    /// <summary>The server profile accepts exactly these types inside an envelope.</summary>
    public static readonly IReadOnlySet<string> ServerSet =
        new HashSet<string>(StringComparer.Ordinal) { Ping, CollectFacts, AgentState };

    /// <summary>Fact section names a <c>collect_facts</c> payload may request (contract (e)).</summary>
    public static readonly IReadOnlySet<string> ServerFactSections = new HashSet<string>(StringComparer.Ordinal)
    {
        "identity", "os", "resources", "network", "firewall", "security", "clock", "runtime",
        "sessions", "hardware", "services", "listening_ports", "updates", "software",
        "processes",
    };
}

/// <summary>The outer <c>envelope</c> object after the shape checks (steps 2 and 3).</summary>
public sealed record EnvelopeWire(string Alg, string KeyId, byte[] SignedBytes, byte[] Signature);

/// <summary>The values of a strictly parsed <c>signed_bytes</c> document.</summary>
public sealed record SignedEnvelope(
    string Id,
    string AgentId,
    string Type,
    long IssuedAt,
    long ExpiresAt,
    string Nonce,
    string KeyId,
    string Alg,
    string Delegation,
    JsonElement Payload,
    string EnvelopeSha256);

/// <summary>Canonical parsing and body building for the signed command envelope.</summary>
public static class CommandEnvelope
{
    public const string Header = "cerberus-agent-envelope.v1";
    public const string Algorithm = "rsa-pkcs1v15-sha256";
    public const int MaxSignedBytes = 8192;
    public const int MaxPayloadBytes = 4096;
    public const int MaxSignatureBytes = 1024;

    private static readonly string[] LineNames =
        { "id", "agent_id", "type", "issued_at", "expires_at", "nonce", "key_id", "alg", "delegation", "payload" };

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    private static readonly JsonSerializerOptions PostVerifyOptions = new(JsonSerializerDefaults.Web);

    /// <summary>Steps 2 and 3: sizes, base64, <c>v == 1</c>, <c>alg</c>, then the outer delegation.</summary>
    public static bool TryReadWire(JsonElement envelope, out EnvelopeWire? wire, out string? code)
    {
        try
        {
            return ReadWire(envelope, out wire, out code);
        }
        catch (InvalidOperationException)
        {
            // Undecodable property name or string value in the unsigned outer envelope.
            wire = null;
            code = EnvelopeCodes.Malformed;
            return false;
        }
    }

    private static bool ReadWire(JsonElement envelope, out EnvelopeWire? wire, out string? code)
    {
        wire = null;
        code = EnvelopeCodes.Malformed;
        if (envelope.ValueKind != JsonValueKind.Object)
            return false;
        if (!envelope.TryGetProperty("v", out var v) || v.ValueKind != JsonValueKind.Number
            || !v.TryGetInt32(out var version) || version != 1)
            return false;
        if (!TryGetString(envelope, "alg", 64, out var alg) || !string.Equals(alg, Algorithm, StringComparison.Ordinal))
            return false;
        if (!TryGetString(envelope, "key_id", 64, out var keyId))
            return false;
        if (!TryGetString(envelope, "signed_bytes", Base64Length(MaxSignedBytes), out var signedB64)
            || !TryDecodeStrictBase64(signedB64, MaxSignedBytes, out var signedBytes))
            return false;
        if (!TryGetString(envelope, "signature", Base64Length(MaxSignatureBytes), out var signatureB64)
            || !TryDecodeStrictBase64(signatureB64, MaxSignatureBytes, out var signature))
            return false;

        if (envelope.TryGetProperty("delegation", out var delegation)
            && delegation.ValueKind != JsonValueKind.Null
            && !(delegation.ValueKind == JsonValueKind.String && delegation.GetString()!.Length == 0))
        {
            code = EnvelopeCodes.DelegationUnsupported;
            return false;
        }

        code = null;
        wire = new EnvelopeWire(alg, keyId, signedBytes, signature);
        return true;
    }

    /// <summary>Step 7: the eleven LF-joined lines, each value strictly checked; the payload is one JSON object.</summary>
    public static bool TryParseSigned(byte[] signedBytes, out SignedEnvelope? envelope)
    {
        envelope = null;
        if (signedBytes.Length == 0 || signedBytes.Length > MaxSignedBytes)
            return false;
        foreach (var b in signedBytes)
        {
            if (b != 0x0A && (b < 0x20 || b > 0x7E))
                return false;
        }

        var lines = Encoding.ASCII.GetString(signedBytes).Split('\n');
        if (lines.Length != LineNames.Length + 1 || !string.Equals(lines[0], Header, StringComparison.Ordinal))
            return false;

        var values = new string[LineNames.Length];
        for (var i = 0; i < LineNames.Length; i++)
        {
            var prefix = LineNames[i] + "=";
            if (!lines[i + 1].StartsWith(prefix, StringComparison.Ordinal))
                return false;
            values[i] = lines[i + 1][prefix.Length..];
        }

        var (id, agentId, type, issued, expires, nonce, keyId, alg, delegation, payloadB64) =
            (values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8], values[9]);
        if (!IsCanonicalUuid(id) || !IsToken(agentId, 256) || !IsTypeName(type) || !IsNonce(nonce)
            || !IsLowerHex(keyId, 16) || !string.Equals(alg, Algorithm, StringComparison.Ordinal)
            || !TryParsePositive(issued, out var issuedAt) || !TryParsePositive(expires, out var expiresAt)
            || !TryDecodeStrictBase64(payloadB64, MaxPayloadBytes, out var payloadBytes)
            || !TryParsePayloadObject(payloadBytes, out var payload))
            return false;

        envelope = new SignedEnvelope(id, agentId, type, issuedAt, expiresAt, nonce, keyId, alg, delegation,
            payload, Sha256Hex(signedBytes));
        return true;
    }

    /// <summary>Step 12: the payload shape each type accepts. Types without a rule here accept any object.</summary>
    public static bool IsValidPayload(string type, JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object)
            return false;
        return type switch
        {
            EnvelopeTypes.Ping => !payload.EnumerateObject().Any(),
            EnvelopeTypes.CollectFacts => IsValidCollectFacts(payload),
            EnvelopeTypes.AgentState => IsValidAgentState(payload),
            _ => true,
        };
    }

    public static string Sha256Hex(ReadOnlySpan<byte> bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    /// <summary>Ack body; deterministic, so a re-sent ack is byte-identical to the first.</summary>
    public static byte[] BuildAckBody(string envelopeSha256, bool accepted, string? reason)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("envelope_sha256", envelopeSha256);
            writer.WriteString("decision", accepted ? "accepted" : "rejected");
            if (reason is null)
                writer.WriteNull("reason");
            else
                writer.WriteString("reason", reason);
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    /// <summary>Result body; serialized once, then stored and re-sent as bytes.</summary>
    public static byte[] BuildResultBody(string status, int? exitCode, string? stderr, object? postVerify, string envelopeSha256)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("status", status);
            if (exitCode is null)
                writer.WriteNull("exit_code");
            else
                writer.WriteNumber("exit_code", exitCode.Value);
            writer.WriteNull("stdout");
            if (stderr is null)
                writer.WriteNull("stderr");
            else
                writer.WriteString("stderr", stderr);
            writer.WritePropertyName("post_verify");
            if (postVerify is null)
                writer.WriteNullValue();
            else
                JsonSerializer.Serialize(writer, postVerify, postVerify.GetType(), PostVerifyOptions);
            writer.WriteString("envelope_sha256", envelopeSha256);
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static bool IsValidCollectFacts(JsonElement payload)
    {
        var properties = payload.EnumerateObject().ToList();
        if (properties.Count == 0)
            return true;
        if (properties.Count != 1 || properties[0].Name != "sections" || properties[0].Value.ValueKind != JsonValueKind.Array)
            return false;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in properties[0].Value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || !EnvelopeTypes.ServerFactSections.Contains(item.GetString()!)
                || !seen.Add(item.GetString()!))
                return false;
        }

        return seen.Count is >= 1 and <= 14;
    }

    private static bool IsValidAgentState(JsonElement payload)
    {
        var hasSeq = false;
        var optional = 0;
        foreach (var property in payload.EnumerateObject())
        {
            var value = property.Value;
            switch (property.Name)
            {
                case "state_seq":
                    if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var seq) || seq < 1)
                        return false;
                    hasSeq = true;
                    break;
                case "registration_state":
                    if (value.ValueKind != JsonValueKind.String || value.GetString() is not ("pending_claim" or "claimed"))
                        return false;
                    optional++;
                    break;
                case "quarantine":
                    if (!IsSingleKeyObject(value, "active") || value.GetProperty("active").ValueKind
                            is not (JsonValueKind.True or JsonValueKind.False))
                        return false;
                    optional++;
                    break;
                case "revoke":
                    if (!IsSingleKeyObject(value, "reason_code")
                        || value.GetProperty("reason_code").ValueKind != JsonValueKind.String
                        || value.GetProperty("reason_code").GetString() is not ("agent_revoked" or "agent_deactivated"))
                        return false;
                    optional++;
                    break;
                default:
                    return false;
            }
        }

        return hasSeq && optional >= 1;
    }

    private static bool IsSingleKeyObject(JsonElement value, string key)
        => value.ValueKind == JsonValueKind.Object
           && value.EnumerateObject().Count() == 1
           && value.TryGetProperty(key, out _);

    private static bool TryParsePayloadObject(byte[] bytes, out JsonElement payload)
    {
        payload = default;
        try
        {
            _ = StrictUtf8.GetString(bytes);
            if (!HasUniqueKeysSingleObject(bytes))
                return false;
            using var document = JsonDocument.Parse(bytes);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return false;
            payload = document.RootElement.Clone();
            return true;
        }
        catch (Exception ex) when (ex is JsonException or DecoderFallbackException or ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>One top-level JSON object with no repeated property name in any object.</summary>
    private static bool HasUniqueKeysSingleObject(byte[] bytes)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions
        {
            CommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            MaxDepth = 32,
        });
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            return false;

        var scopes = new Stack<HashSet<string>?>();
        scopes.Push(new HashSet<string>(StringComparer.Ordinal));
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    scopes.Push(new HashSet<string>(StringComparer.Ordinal));
                    break;
                case JsonTokenType.StartArray:
                    scopes.Push(null);
                    break;
                case JsonTokenType.EndObject:
                case JsonTokenType.EndArray:
                    scopes.Pop();
                    if (scopes.Count == 0)
                        return !reader.Read();
                    break;
                case JsonTokenType.PropertyName:
                    if (scopes.Peek() is not { } names || !names.Add(reader.GetString()!))
                        return false;
                    break;
            }
        }

        return false;
    }

    private static bool TryGetString(JsonElement obj, string name, int maxLength, out string value)
    {
        value = string.Empty;
        if (!obj.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String)
            return false;
        value = element.GetString()!;
        return value.Length <= maxLength;
    }

    private static int Base64Length(int decodedBytes) => (decodedBytes + 2) / 3 * 4;

    /// <summary>Standard padded base64 in canonical form only (no whitespace, no stray padding bits).</summary>
    private static bool TryDecodeStrictBase64(string value, int maxDecoded, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (value.Length == 0 || value.Length % 4 != 0 || value.Length > Base64Length(maxDecoded))
            return false;
        foreach (var c in value)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '='))
                return false;
        }

        var buffer = new byte[value.Length / 4 * 3];
        if (!Convert.TryFromBase64String(value, buffer, out var written) || written > maxDecoded)
            return false;
        bytes = buffer[..written];
        return string.Equals(Convert.ToBase64String(bytes), value, StringComparison.Ordinal);
    }

    private static bool TryParsePositive(string value, out long parsed)
    {
        parsed = 0;
        return value.Length is >= 1 and <= 18 && value[0] != '0' && value.All(char.IsAsciiDigit)
               && long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out parsed) && parsed > 0;
    }

    private static bool IsCanonicalUuid(string value)
    {
        if (value.Length != 36)
            return false;
        for (var i = 0; i < value.Length; i++)
        {
            var dash = i is 8 or 13 or 18 or 23;
            if (dash ? value[i] != '-' : !(char.IsAsciiDigit(value[i]) || value[i] is >= 'a' and <= 'f'))
                return false;
        }

        return true;
    }

    private static bool IsLowerHex(string value, int length)
        => value.Length == length && value.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f');

    private static bool IsToken(string value, int maxLength)
        => value.Length >= 1 && value.Length <= maxLength && value.All(c => c is > ' ' and <= '~');

    private static bool IsTypeName(string value)
        => value.Length is >= 1 and <= 128 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');

    private static bool IsNonce(string value)
        => value.Length is >= 1 and <= 128 && value.All(c => c is > ' ' and <= '~' && c != ':');
}
