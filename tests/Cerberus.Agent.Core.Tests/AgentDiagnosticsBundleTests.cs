using Cerberus.Agent.App.Diagnostics;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentDiagnosticsBundleTests
{
    [Fact]
    public void Redact_RemovesCredentialMarkersFromDiagnosticsText()
    {
        var raw = """
        {
          "refresh_token": "token-value",
          "client_secret": "secret-value",
          "private_key": "-----BEGIN PRIVATE KEY-----abc",
          "message": "safe status"
        }
        """;

        var redacted = AgentDiagnosticsBundle.Redact(raw);

        Assert.DoesNotContain("token-value", redacted);
        Assert.DoesNotContain("secret-value", redacted);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", redacted);
        Assert.Contains("safe status", redacted);
        Assert.Contains("[REDACTED]", redacted);
    }
}
