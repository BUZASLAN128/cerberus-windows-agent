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
}
