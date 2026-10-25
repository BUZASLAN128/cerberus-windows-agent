using Cerberus.Agent.Observability;

namespace Cerberus.Agent.Core.Tests;

public sealed class SanitizerTests
{
    [Fact]
    public void Redact_RemovesJwtTailscaleKeyAndPrivateKeyLikeValues()
    {
        var input = """
        Authorization: Bearer eyJaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc
        tailscale_authkey=hskey-auth-secretvalue
        private_key=-----BEGIN
        password=supersafe
        """;

        var redacted = Sanitizer.Redact(input);

        Assert.DoesNotContain("eyJaaaaaaaaaaa", redacted);
        Assert.DoesNotContain("hskey-auth-secretvalue", redacted);
        Assert.DoesNotContain("supersafe", redacted);
        Assert.Contains("[REDACTED_JWT]", redacted);
        Assert.Contains("hskey-auth-[REDACTED]", redacted);
    }

    [Fact]
    public void Redact_RemovesCommonApiKeysAndLongEncodedSecrets()
    {
        var input = """
        api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890
        public_key=pk-abcdefghijklmnopqrstuvwxyz1234567890
        tailscale=tskey-auth-abcdefghijklmnopqrstuvwxyz1234567890
        blob=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo2Nzg5MDEyMzQ1Njc4OTA=
        refresh_token=secret-refresh-value
        """;

        var redacted = Sanitizer.Redact(input);

        Assert.DoesNotContain("sk-abcdefghijklmnopqrstuvwxyz", redacted);
        Assert.DoesNotContain("pk-abcdefghijklmnopqrstuvwxyz", redacted);
        Assert.DoesNotContain("tskey-auth-abcdefghijklmnopqrstuvwxyz", redacted);
        Assert.DoesNotContain("QUJDREVGR0hJSkt", redacted);
        Assert.DoesNotContain("secret-refresh-value", redacted);
        Assert.Contains("[REDACTED_API_KEY]", redacted);
        Assert.Contains("tskey-auth-[REDACTED]", redacted);
        Assert.Contains("[REDACTED_SECRET]", redacted);
    }

    [Fact]
    public void Redact_RedactsStructuredJsonSensitiveFields()
    {
        var input = """
        {"access_token":"abc123","nested":{"password":"secret-value"},"safe":"visible"}
        """;

        var redacted = Sanitizer.Redact(input);

        Assert.DoesNotContain("abc123", redacted);
        Assert.DoesNotContain("secret-value", redacted);
        Assert.Contains("\"access_token\":\"[REDACTED]\"", redacted);
        Assert.Contains("\"password\":\"[REDACTED]\"", redacted);
        Assert.Contains("visible", redacted);
    }

    [Fact]
    public void Redact_RedactsGeneratedSensitiveJsonValues()
    {
        for (var i = 0; i < 25; i++)
        {
            var secret = Convert.ToBase64String(Guid.NewGuid().ToByteArray()) +
                         Convert.ToBase64String(Guid.NewGuid().ToByteArray());
            var input = $$"""
            {"refresh_token":"{{secret}}","items":[{"client_secret":"{{secret}}"}],"label":"safe-{{i}}"}
            """;

            var redacted = Sanitizer.Redact(input);

            Assert.DoesNotContain(secret, redacted);
            Assert.Contains("safe-" + i, redacted);
            Assert.Contains("\"refresh_token\":\"[REDACTED]\"", redacted);
            Assert.Contains("\"client_secret\":\"[REDACTED]\"", redacted);
        }
    }
    private const string Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Hex63 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
    private static readonly string FpA = "sha256:" + string.Concat(Enumerable.Repeat("0123456789abcdef", 4));
    private static readonly string FpB = "sha256:" + new string('b', 64);

    [Theory]
    [InlineData("Agent key fingerprint={A}")]
    [InlineData("Agent key fingerprint replaced old={A} new={B}")]
    [InlineData("reenrollment_proof_required fingerprint={A}")]
    public void Redact_KeepsTheSha256KeyFingerprintInOperatorLogLines(string template)
    {
        var line = template.Replace("{A}", FpA).Replace("{B}", FpB);

        Assert.Equal(line, Sanitizer.Redact(line));
    }

    [Fact]
    public void Redact_StillRedactsSecretsNextToAFingerprint()
    {
        var bareHex = string.Concat(Enumerable.Repeat("0123456789abcdef", 4));
        var base64 = Convert.ToBase64String(Enumerable.Range(1, 36).Select(i => (byte)(i * 7)).ToArray());
        Assert.Equal(48, base64.Length);

        var redacted = Sanitizer.Redact($"fingerprint={FpA} bare={bareHex} upper={bareHex.ToUpperInvariant()} blob={base64}");

        Assert.Contains(FpA, redacted);
        Assert.Equal(1, redacted.Split(FpA).Length - 1);
        Assert.DoesNotContain(bareHex, redacted.Replace(FpA, ""));
        Assert.DoesNotContain(bareHex.ToUpperInvariant(), redacted);
        Assert.DoesNotContain(base64, redacted);
        Assert.Equal(3, redacted.Split("[REDACTED_SECRET]").Length - 1);
    }

    [Fact]
    public void Redact_StructuredJsonStillRedactsSensitiveKeysNextToAFingerprint()
    {
        var redacted = Sanitizer.Redact($"{{\"fingerprint\":\"{FpA}\",\"password\":\"hunter2\"}}");

        Assert.Contains(FpA, redacted);
        Assert.Contains("\"password\":\"[REDACTED]\"", redacted);
        Assert.DoesNotContain("hunter2", redacted);
    }

    [Fact]
    public void Redact_StructuredJsonKeepsFingerprintInsideALogLineAndRedactsSensitiveKeys()
    {
        var input = $"{{\"log\":\"Agent key fingerprint={FpA}\",\"nested\":[{{\"client_secret\":\"s3cr3t-value\"}}],\"token\":\"abc123\"}}";

        var redacted = Sanitizer.Redact(input);

        Assert.Equal(1, redacted.Split(FpA).Length - 1);
        Assert.Contains("\"token\":\"[REDACTED]\"", redacted);
        Assert.Contains("\"client_secret\":\"[REDACTED]\"", redacted);
        Assert.DoesNotContain("s3cr3t-value", redacted);
        Assert.DoesNotContain("abc123", redacted);
        Assert.DoesNotContain('\u0001', redacted);
    }

    [Theory]
    [InlineData("sha256:" + Hex + "0")]
    [InlineData("xsha256:" + Hex)]
    [InlineData("sha256:" + Hex + "=")]
    [InlineData("SHA256:" + Hex)]
    [InlineData("sha256:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("sha256:" + Hex63)]
    [InlineData(Hex)]
    public void Redact_DoesNotExemptValuesThatAreNotTheExactFingerprintForm(string value)
    {
        var redacted = Sanitizer.Redact("fingerprint=" + value);

        Assert.DoesNotContain("0123456789abcdef0123456789abcdef", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[REDACTED_SECRET]", redacted);
    }
}
