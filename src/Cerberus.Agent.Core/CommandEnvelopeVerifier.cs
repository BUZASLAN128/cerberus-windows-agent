using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

/// <summary>
/// Outcome of one verification stage. <see cref="Code"/> is null when the stage passed.
/// <see cref="Envelope"/> is set once the signed bytes were parsed (step 7 onward), so
/// an acked rejection can name the signed id and <c>envelope_sha256</c>.
/// </summary>
public sealed record EnvelopeCheck(int Step, string? Code, bool AckRejected, SignedEnvelope? Envelope)
{
    public bool Passed => Code is null;

    internal static EnvelopeCheck Fail(int step, string code, bool ack = false, SignedEnvelope? envelope = null)
        => new(step, code, ack, envelope);
}

/// <summary>
/// Steps 1-12 and 14-16 of the envelope verification order (contract v1). The replay
/// lookup (13) and the reservation (18) belong to <see cref="CommandReplayStore"/>.
/// </summary>
public sealed class CommandEnvelopeVerifier
{
    public const long MaxTtlSeconds = 300;
    public const long SkewSeconds = 60;
    private const int MinModulusBits = 2048;

    private readonly IReadOnlyList<CommandTrustAnchor> _anchors;
    private readonly IReadOnlySet<string> _allowedTypes;

    /// <summary>
    /// Anchors under 2048 bits or whose key id is not the SPKI hash are not trusted and are
    /// left out, so a weak or mislabeled key can never verify an envelope.
    /// </summary>
    public CommandEnvelopeVerifier(IEnumerable<CommandTrustAnchor> anchors, IReadOnlySet<string> allowedTypes, IAgentLogger? log = null)
    {
        ArgumentNullException.ThrowIfNull(anchors);
        _allowedTypes = allowedTypes ?? throw new ArgumentNullException(nameof(allowedTypes));
        var usable = new List<CommandTrustAnchor>();
        foreach (var anchor in anchors)
        {
            if (IsUsable(anchor))
                usable.Add(anchor);
            else
                (log ?? NullAgentLogger.Instance).Warn($"Command trust anchor key_id={anchor.KeyId} ignored: weak or mislabeled key.");
        }

        _anchors = usable;
    }

    public int AnchorCount => _anchors.Count;

    /// <summary>Steps 1-12 for one pending entry against the current agent id.</summary>
    public EnvelopeCheck VerifyEntry(AgentCommand entry, string currentAgentId)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (!HasEnvelope(entry))
            return EnvelopeCheck.Fail(1, EnvelopeCodes.Unsigned);

        if (!CommandEnvelope.TryReadWire(entry.Envelope!.Value, out var wire, out var wireCode))
            return EnvelopeCheck.Fail(wireCode == EnvelopeCodes.DelegationUnsupported ? 3 : 2, wireCode!);

        if (_anchors.Count == 0)
            return EnvelopeCheck.Fail(4, EnvelopeCodes.NoTrustAnchor);

        var anchor = _anchors.FirstOrDefault(a => string.Equals(a.KeyId, wire!.KeyId, StringComparison.Ordinal));
        if (anchor is null)
            return EnvelopeCheck.Fail(5, EnvelopeCodes.KeyUnknown);

        if (!VerifySignature(anchor, wire!.SignedBytes, wire.Signature))
            return EnvelopeCheck.Fail(6, EnvelopeCodes.SignatureInvalid);

        if (!CommandEnvelope.TryParseSigned(wire.SignedBytes, out var signed))
            return EnvelopeCheck.Fail(7, EnvelopeCodes.Malformed);

        if (!string.Equals(signed!.AgentId, currentAgentId, StringComparison.Ordinal))
            return EnvelopeCheck.Fail(8, EnvelopeCodes.AgentMismatch, envelope: signed);

        if (!string.Equals(entry.Id, signed.Id, StringComparison.Ordinal)
            || !string.Equals(entry.Type, signed.Type, StringComparison.Ordinal)
            || !string.Equals(wire.KeyId, signed.KeyId, StringComparison.Ordinal)
            || !string.Equals(wire.Alg, signed.Alg, StringComparison.Ordinal))
            return EnvelopeCheck.Fail(9, EnvelopeCodes.Mismatch, ack: true, envelope: signed);

        if (signed.Delegation.Length != 0)
            return EnvelopeCheck.Fail(10, EnvelopeCodes.DelegationUnsupported, ack: true, envelope: signed);

        if (!_allowedTypes.Contains(signed.Type))
            return EnvelopeCheck.Fail(11, EnvelopeCodes.TypeNotAllowed, ack: true, envelope: signed);

        if (!CommandEnvelope.IsValidPayload(signed.Type, signed.Payload))
            return EnvelopeCheck.Fail(12, EnvelopeCodes.PayloadInvalid, ack: true, envelope: signed);

        return new EnvelopeCheck(12, null, false, signed);
    }

    /// <summary>Steps 14-16: time window, store reset floor, nonce reuse.</summary>
    public static EnvelopeCheck CheckReplayWindow(SignedEnvelope signed, long nowUnix, long resetAt, bool nonceUsedElsewhere)
    {
        if (signed.ExpiresAt <= signed.IssuedAt || signed.ExpiresAt - signed.IssuedAt > MaxTtlSeconds)
            return EnvelopeCheck.Fail(14, EnvelopeCodes.TtlInvalid, ack: true, envelope: signed);
        if (nowUnix < signed.IssuedAt - SkewSeconds)
            return EnvelopeCheck.Fail(14, EnvelopeCodes.NotYetValid, ack: true, envelope: signed);
        if (nowUnix > signed.ExpiresAt + SkewSeconds)
            return EnvelopeCheck.Fail(14, EnvelopeCodes.Expired, ack: true, envelope: signed);
        if (signed.IssuedAt < resetAt)
            return EnvelopeCheck.Fail(15, EnvelopeCodes.IssuedBeforeReset, ack: true, envelope: signed);
        if (nonceUsedElsewhere)
            return EnvelopeCheck.Fail(16, EnvelopeCodes.NonceReused, ack: true, envelope: signed);
        return new EnvelopeCheck(16, null, false, signed);
    }

    /// <summary>True when the entry carries a non-null <c>envelope</c> member.</summary>
    public static bool HasEnvelope(AgentCommand entry)
        => entry.Envelope is { } element
           && element.ValueKind is not (System.Text.Json.JsonValueKind.Null or System.Text.Json.JsonValueKind.Undefined);

    private static bool VerifySignature(CommandTrustAnchor anchor, byte[] signedBytes, byte[] signature)
    {
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(anchor.Spki, out _);
            return rsa.KeySize >= MinModulusBits
                   && rsa.VerifyData(signedBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool IsUsable(CommandTrustAnchor anchor)
    {
        if (anchor?.Spki is null || anchor.KeyId is null)
            return false;
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(anchor.Spki, out var read);
            return read == anchor.Spki.Length && rsa.KeySize >= MinModulusBits
                   && string.Equals(anchor.KeyId, AgentProfileMetadata.ComputeKeyId(anchor.Spki), StringComparison.Ordinal);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
