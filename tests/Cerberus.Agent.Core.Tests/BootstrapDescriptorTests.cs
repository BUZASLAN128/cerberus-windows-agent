using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class BootstrapDescriptorTests
{
    [Fact]
    public void Validate_Accepts_CurrentDescriptorShape()
    {
        var descriptor = new BootstrapDescriptor(
            SchemaVersion: "agent.bootstrap.v1",
            DescriptorId: "d1",
            Issuer: "https://sso.example",
            Audience: "client",
            BootstrapApiBaseUrl: "https://api.example",
            TelemetryBaseUrl: "https://api.example",
            ConfigVersion: "agent-config.v1",
            IssuedAtUtc: DateTimeOffset.UtcNow.ToString("O"),
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(5).ToString("O"));

        BootstrapDescriptorValidator.Validate(descriptor);
    }

    [Fact]
    public void Validate_Rejects_ExpiredDescriptor()
    {
        var descriptor = new BootstrapDescriptor(
            SchemaVersion: "agent.bootstrap.v1",
            DescriptorId: "d1",
            Issuer: "https://sso.example",
            Audience: "client",
            BootstrapApiBaseUrl: "https://api.example",
            TelemetryBaseUrl: "https://api.example",
            ConfigVersion: "agent-config.v1",
            IssuedAtUtc: DateTimeOffset.UtcNow.AddMinutes(-10).ToString("O"),
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"));

        Assert.Throws<InvalidOperationException>(() => BootstrapDescriptorValidator.Validate(descriptor));
    }

    [Fact]
    public void ResolveDescriptorUri_UsesIssuerWellKnown_WhenNoOverride()
    {
        var uri = BootstrapDescriptorValidator.ResolveDescriptorUri(
            new Uri("https://sso.example/base/"),
            explicitDescriptorUrl: null);

        Assert.Equal(
            "https://sso.example/base/.well-known/cerberus-agent-bootstrap.json",
            uri.ToString());
    }
}
