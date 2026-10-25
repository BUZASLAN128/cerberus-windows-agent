using System.Text.Json;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.Core.Tests;

// Structured JSON is re-serialised before the regex passes; a '+' must not turn into an escape that splits a token.
public sealed class SanitizerJsonEncodingTests
{
    [Fact]
    public void Redact_Base64TokenWithPlusUnderNonSensitiveKey_IsRedactedCompletely()
    {
        const string head = "AAAAAAAAAAAAAAAAAAAAAAAA";
        const string tail = "BBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        var input = $$"""{"note":"{{head}}+{{tail}}","other":"visible"}""";

        var redacted = Sanitizer.Redact(input);

        Assert.DoesNotContain(head, redacted, StringComparison.Ordinal);
        Assert.DoesNotContain(tail, redacted, StringComparison.Ordinal);
        Assert.Contains("[REDACTED_SECRET]", redacted, StringComparison.Ordinal);
        Assert.Contains("visible", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_FingerprintFollowedByPlus_IsNotKeptAsFingerprint()
    {
        var hex = new string('a', 64);
        var input = $$"""{"note":"sha256:{{hex}}+"}""";

        var redacted = Sanitizer.Redact(input);

        Assert.DoesNotContain(hex, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_StandaloneFingerprintInJson_StaysVisible()
    {
        var fingerprint = "sha256:" + new string('b', 64);
        var input = $$"""{"fingerprint":"{{fingerprint}}","sk":"x"}""";

        Assert.Contains(fingerprint, Sanitizer.Redact(input), StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_StructuredJson_KeepsControlCharactersAndQuotesEscaped()
    {
        var token = new string('A', 24) + "+" + new string('B', 28);
        // JSON text with \n, \u0001 and \" escapes inside the string value.
        var input = @"{""note"":""line1\nline2\u0001 \""q\"" " + token + @"""}";

        var redacted = Sanitizer.Redact(input);

        Assert.DoesNotContain('\n', redacted);
        Assert.DoesNotContain('\u0001', redacted);
        using var doc = JsonDocument.Parse(redacted);
        var note = doc.RootElement.GetProperty("note").GetString()!;
        Assert.Contains("\"q\"", note, StringComparison.Ordinal);
        Assert.DoesNotContain(token, note, StringComparison.Ordinal);
    }
}
