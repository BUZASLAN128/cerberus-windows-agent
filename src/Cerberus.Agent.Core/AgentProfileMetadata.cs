using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.Core;

public sealed record AgentTimingBounds(
    int PollFloor,
    int PollCeiling,
    int SnapshotFloor,
    int SnapshotCeiling,
    int SnapshotDefault);

/// <summary>A command trust anchor: an RSA public key and its 16-hex key id.</summary>
public sealed record CommandTrustAnchor(string KeyId, byte[] Spki);

/// <summary>
/// Reads the build metadata of this assembly: timing bounds and command trust anchors.
/// Build metadata is the only source; no other input is consulted.
/// </summary>
public static class AgentProfileMetadata
{
    public const string AnchorsMetadataName = "AgentCommandTrustAnchorsB64";
    private const int MinAnchorModulusBits = 2048;

    private static readonly Lazy<AgentTimingBounds> TimingBounds =
        new(() => ParseTiming(ReadMetadata));

    public static AgentTimingBounds Timing => TimingBounds.Value;

    /// <summary>
    /// Anchors embedded in this build. An anchor equal to an update manifest public key
    /// is dropped and logged, so a manifest key can never authorize commands.
    /// </summary>
    public static IReadOnlyList<CommandTrustAnchor> LoadCommandAnchors(
        IEnumerable<string> manifestPublicKeyPems,
        IAgentLogger? log = null)
        => ParseAnchors(ReadMetadata(AnchorsMetadataName), manifestPublicKeyPems, log);

    public static AgentTimingBounds ParseTiming(Func<string, string?> read)
    {
        var bounds = new AgentTimingBounds(
            ReadInt(read, "AgentPollFloorSeconds"),
            ReadInt(read, "AgentPollCeilingSeconds"),
            ReadInt(read, "AgentSnapshotFloorSeconds"),
            ReadInt(read, "AgentSnapshotCeilingSeconds"),
            ReadInt(read, "AgentSnapshotDefaultSeconds"));

        if (bounds.PollFloor < 1 || bounds.SnapshotFloor < 1
            || bounds.PollFloor > bounds.PollCeiling
            || bounds.SnapshotFloor > bounds.SnapshotCeiling
            || bounds.SnapshotDefault < bounds.SnapshotFloor
            || bounds.SnapshotDefault > bounds.SnapshotCeiling)
        {
            throw new InvalidOperationException("Agent timing metadata is inconsistent.");
        }

        return bounds;
    }

    /// <summary>
    /// Parses the anchor value: standard base64 of UTF-8 text, one base64 SPKI per LF-separated line.
    /// Malformed, weak or duplicate lines are skipped and logged; fewer anchors only narrows trust.
    /// </summary>
    public static IReadOnlyList<CommandTrustAnchor> ParseAnchors(
        string? anchorsB64,
        IEnumerable<string>? manifestPublicKeyPems,
        IAgentLogger? log)
    {
        var anchors = new List<CommandTrustAnchor>();
        if (string.IsNullOrWhiteSpace(anchorsB64))
            return anchors;

        string text;
        try
        {
            text = Encoding.UTF8.GetString(Convert.FromBase64String(anchorsB64.Trim()));
        }
        catch (FormatException)
        {
            log?.Warn("Command trust anchors ignored: value is not valid base64.");
            return anchors;
        }

        var manifestKeys = ReadManifestKeys(manifestPublicKeyPems);
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
                continue;

            if (!TryReadAnchor(line, out var spki, out var parameters))
            {
                log?.Warn("Command trust anchor skipped: not a valid RSA public key of at least 2048 bits.");
                continue;
            }

            var keyId = ComputeKeyId(spki);
            if (manifestKeys.Any(m => SameKey(m, parameters)))
            {
                log?.Warn($"Command trust anchor key_id={keyId} dropped: it equals an update manifest public key.");
                continue;
            }

            if (anchors.Any(a => string.Equals(a.KeyId, keyId, StringComparison.Ordinal)))
                continue;

            anchors.Add(new CommandTrustAnchor(keyId, spki));
        }

        return anchors;
    }

    /// <summary>First 16 lowercase hex characters of SHA-256 over the SPKI DER.</summary>
    public static string ComputeKeyId(byte[] spki)
        => Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant()[..16];

    private static bool TryReadAnchor(string line, out byte[] spki, out RSAParameters parameters)
    {
        spki = Array.Empty<byte>();
        parameters = default;
        try
        {
            spki = Convert.FromBase64String(line);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(spki, out var read);
            if (read != spki.Length || rsa.KeySize < MinAnchorModulusBits)
                return false;
            parameters = rsa.ExportParameters(false);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    private static List<RSAParameters> ReadManifestKeys(IEnumerable<string>? pems)
    {
        var keys = new List<RSAParameters>();
        foreach (var pem in pems ?? Array.Empty<string>())
        {
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(pem);
                keys.Add(rsa.ExportParameters(false));
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException or ArgumentException)
            {
                // A manifest key that does not parse cannot match an anchor.
            }
        }

        return keys;
    }

    private static bool SameKey(RSAParameters left, RSAParameters right)
        => left.Modulus is not null && right.Modulus is not null
           && left.Exponent is not null && right.Exponent is not null
           && left.Modulus.AsSpan().SequenceEqual(right.Modulus)
           && left.Exponent.AsSpan().SequenceEqual(right.Exponent);

    private static int ReadInt(Func<string, string?> read, string key)
    {
        var value = read(key);
        if (value is null || value.Length == 0 || value.Length > 9 || !value.All(char.IsAsciiDigit)
            || !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
        {
            throw new InvalidOperationException($"Agent timing metadata '{key}' is missing or not an integer.");
        }

        return parsed;
    }

    private static string? ReadMetadata(string key)
        => typeof(AgentProfileMetadata).Assembly
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attr => string.Equals(attr.Key, key, StringComparison.Ordinal))?
            .Value;
}
