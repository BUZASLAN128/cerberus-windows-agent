using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.App.Legal;

internal static class AgentPrivacyDocument
{
    private static readonly Lazy<string> Digest = new(() =>
    {
        using var stream = typeof(AgentPrivacyDocument).Assembly.GetManifestResourceStream("Cerberus.Agent.PrivacyNotice")
            ?? throw new InvalidOperationException("Embedded privacy notice is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return ComputeSha256(reader.ReadToEnd());
    });

    public static string Sha256 => Digest.Value;

    // Consent follows document content, with platform line endings/BOM treated as transport formatting.
    internal static string ComputeSha256(string text)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text.TrimStart('\uFEFF').ReplaceLineEndings("\n"))));
}
