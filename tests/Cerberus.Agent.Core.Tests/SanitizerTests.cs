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
}
