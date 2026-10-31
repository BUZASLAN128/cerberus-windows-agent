using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentWakeupProtocolTests
{
    [Theory]
    [InlineData("{\"version\":1,\"path\":\"/api/ws\"}", true)]
    [InlineData("{\"version\":2,\"path\":\"/api/ws\"}", false)]
    [InlineData("{\"version\":1,\"path\":\"//other/ws\"}", false)]
    [InlineData("{\"version\":1,\"path\":\"/api/ws\",\"extra\":true}", false)]
    [InlineData("{\"version\":1,\"version\":1,\"path\":\"/api/ws\"}", false)]
    [InlineData("{\"version\":\"1\",\"path\":\"/api/ws\"}", false)]
    [InlineData("null", false)]
    [InlineData("[]", false)]
    public void Discovery_AcceptsOnlyValidatedV1Shape(string json, bool expected)
    {
        using var document = JsonDocument.Parse(json);
        Assert.Equal(expected, AgentWakeupProtocol.TryReadDiscovery(new Uri("https://agent.example"), document.RootElement, out _));
    }

    [Fact]
    public void Heartbeat_LegacyResponseDoesNotRequireDiscovery()
    {
        const string json = "{\"pending_commands\":[],\"next_poll_seconds\":30,\"next_snapshot_seconds\":300,\"server_time\":1}";
        var response = JsonSerializer.Deserialize<HeartbeatResponse>(json)!;
        Assert.Null(response.Wakeup);
        Assert.False(AgentWakeupProtocol.TryReadDiscovery(new Uri("https://agent.example"), response.Wakeup, out _));
    }

    [Fact]
    public void ResolveEndpoint_PreservesHttpsAuthorityAndExplicitPort()
    {
        Assert.True(AgentWakeupProtocol.TryResolveEndpoint(new Uri("https://agent.example:8443/base"), 1,
            "/api/v1/agents/123/wakeup", out var endpoint));
        Assert.Equal("wss://agent.example:8443/api/v1/agents/123/wakeup", endpoint!.AbsoluteUri);
    }

    [Fact]
    public void ResolveEndpoint_PreservesDefaultTlsPort()
    {
        Assert.True(AgentWakeupProtocol.TryResolveEndpoint(new Uri("https://agent.example"), 1, "/ws", out var endpoint));
        Assert.Equal("wss", endpoint!.Scheme);
        Assert.Equal(443, endpoint.Port);
    }

    [Theory]
    [InlineData("https://other.example/ws")]
    [InlineData("//other.example/ws")]
    [InlineData("/\\other.example/ws")]
    [InlineData("/%2f%2fother.example/ws")]
    [InlineData("/agents/../other")]
    [InlineData("/agents/./other")]
    [InlineData("/ws?token=secret")]
    [InlineData("/ws#fragment")]
    [InlineData("relative/path")]
    public void ResolveEndpoint_RejectsAmbiguousOrForeignPaths(string path)
        => Assert.False(AgentWakeupProtocol.TryResolveEndpoint(new Uri("https://agent.example"), 1, path, out _));

    [Fact]
    public void ResolveEndpoint_RejectsUnknownVersionAndNonHttpsOrigin()
    {
        Assert.False(AgentWakeupProtocol.TryResolveEndpoint(new Uri("https://agent.example"), 2, "/ws", out _));
        Assert.False(AgentWakeupProtocol.TryResolveEndpoint(new Uri("http://agent.example"), 1, "/ws", out _));
        Assert.False(AgentWakeupProtocol.TryResolveEndpoint(new Uri("https://user@agent.example"), 1, "/ws", out _));
    }

    [Theory]
    [InlineData("{\"type\":\"command_available\",\"version\":1}", true)]
    [InlineData("{\"version\":1,\"type\":\"command_available\"}", true)]
    [InlineData("{\"type\":\"command_available\",\"version\":2}", false)]
    [InlineData("{\"type\":\"command_available\",\"version\":1,\"payload\":{}}", false)]
    [InlineData("{\"type\":\"command_available\",\"type\":\"command_available\",\"version\":1}", false)]
    [InlineData("{\"type\":\"command_available\"}", false)]
    [InlineData("not json", false)]
    public void Notification_IsStrictAndContainsNoCommand(string json, bool expected)
        => Assert.Equal(expected, AgentWakeupProtocol.IsCommandAvailable(Encoding.UTF8.GetBytes(json)));

    [Fact]
    public void Notification_RejectsOversizedInput()
        => Assert.False(AgentWakeupProtocol.IsCommandAvailable(new byte[AgentWakeupProtocol.MaxNotificationBytes + 1]));
}
