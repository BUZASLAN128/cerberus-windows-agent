using System.Diagnostics;
using System.Text.Json;
using Cerberus.Agent.App.Telemetry.Sections;
using Xunit.Abstractions;

namespace Cerberus.Agent.Core.Tests;

// Read-only local probe evidence; this does not establish SYSTEM/service permissions.
[Collection("FailedLogonCursor")]
public sealed class SecurityTelemetryParityTests(ITestOutputHelper output)
{
    [Fact]
    public async Task DefaultCollector_ProfilesExposeTheSameBoundedSecurityFields()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var watch = Stopwatch.StartNew();
        var result = await new ServerSectionBudget(new SecurityTelemetrySectionCollector(), TimeProvider.System)
            .CollectAsync(ServerFactJson.Context(), stop.Token);
        var node = JsonSerializer.SerializeToNode(result)!.AsObject();
        output.WriteLine($"security elapsed_ms={watch.ElapsedMilliseconds}; status={node["status"]}");
        foreach (var field in new[] { "failed_logons", "successful_logons", "log_cleared", "local_admins", "unexpected_shutdowns", "defender_av", "smb1" })
        {
            Assert.True(node.TryGetPropertyValue(field, out var value), $"Missing security field: {field}");
            output.WriteLine($"{field} status={value?["status"]}");
        }
    }
}
