using System.Text.Json;
using Cerberus.Agent.Integrations.Tailscale;

namespace Cerberus.Agent.Core.Tests;

public sealed class TailscaleStatusProbeTests
{
    [Fact]
    public void CreateStatusStartInfo_UsesReadOnlyStatusCommand()
    {
        var psi = TailscaleStatusProbe.CreateStatusStartInfo();

        Assert.Equal("tailscale", psi.FileName);
        Assert.Equal("status --json", psi.Arguments);
        Assert.DoesNotContain(" up", psi.Arguments);
        Assert.DoesNotContain("login", psi.Arguments);
    }

    [Fact]
    public void ParseStatusSnapshot_ExcludesPeerMapAndKeepsSelfState()
    {
        var json = """
        {
          "BackendState": "Running",
          "Self": {
            "DNSName": "host.tailnet.ts.net.",
            "Online": true,
            "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"]
          },
          "Peer": {
            "peer1": {
              "DNSName": "other.tailnet.ts.net.",
              "TailscaleIPs": ["100.64.0.2"]
            }
          }
        }
        """;

        var (connected, snapshot) = TailscaleStatusProbe.ParseStatusSnapshot(json);
        var serialized = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.True(connected);
        Assert.Contains("100.64.0.1", serialized);
        Assert.DoesNotContain("peer1", serialized);
        Assert.DoesNotContain("100.64.0.2", serialized);
    }
}
