using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentApiClientTelemetryTests
{
    [Fact]
    public async Task ManagedAccountManifest_UsesSignedAgentScopedGetWithEmptyBody()
    {
        var handler = new CaptureHandler("""{"version":"v","hash":"h","fresh_until":"2026-09-06T12:05:00Z","require_manifest_before_unlock":true,"accounts":[]}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var manifest = await client.GetManagedAccountManifestAsync(default);
        Assert.True(manifest.RequireManifestBeforeUnlock);
        Assert.Empty(manifest.Accounts);
        Assert.Equal(HttpMethod.Get, handler.CapturedRequest!.Method);
        Assert.Equal("/api/v1/agents/a1/managed-accounts/manifest", handler.CapturedRequest.RequestUri!.AbsolutePath);
        Assert.Equal("a1", Assert.Single(handler.CapturedRequest.Headers.GetValues("X-Agent-Id")));
        Assert.Equal("signature", Assert.Single(handler.CapturedRequest.Headers.GetValues("X-Signature")));
        Assert.Equal("", handler.CapturedBody);
    }

    [Fact]
    public async Task SubmitSnapshotAsync_PostsSignedSnapshotEndpoint()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var snapshot = AgentSnapshotFactory.Create(
            Metadata(),
            DateTimeOffset.Parse("2026-05-07T00:00:00Z"),
            new Dictionary<string, object?> { ["identity"] = new { status = "ok" } });

        var ack = await client.SubmitSnapshotAsync(snapshot, CancellationToken.None);

        Assert.Equal("accepted", ack.Status);
        Assert.Equal("/api/v1/agents/a1/snapshot", handler.CapturedRequest!.RequestUri!.AbsolutePath);
        Assert.Contains("X-Signature", handler.CapturedRequest.Headers.Select(h => h.Key));
        using var doc = JsonDocument.Parse(handler.CapturedBody!);
        Assert.Equal(AgentSchemaVersions.Snapshot, doc.RootElement.GetProperty("schema_version").GetString());
    }

    [Fact]
    public async Task SubmitEventsAndProbeResult_PostExpectedEndpoints()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var events = AgentTelemetryFactory.CreateEvents(
            Metadata(),
            new[]
            {
                new AgentEventItem(
                    EventId: "evt-12345678",
                    Type: "agent.started",
                    OccurredAt: "2026-05-07T00:00:00Z",
                    Severity: "info",
                    Payload: new Dictionary<string, object?>()),
            });
        await client.SubmitEventsAsync(events, CancellationToken.None);
        Assert.Equal("/api/v1/agents/a1/events", handler.CapturedRequest!.RequestUri!.AbsolutePath);

        var probe = AgentTelemetryFactory.CreateProbeResult(
            Metadata(),
            resultId: "res-12345678",
            probeId: "agent.self_test",
            status: "ok",
            payload: new Dictionary<string, object?>());
        await client.SubmitProbeResultAsync(probe, CancellationToken.None);
        Assert.Equal("/api/v1/agents/a1/probe-results", handler.CapturedRequest!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SafeTelemetrySubmit_RetriesSnapshotProbeAndDiagnosticOnceOnTransientOutage()
    {
        var handler = new TransientThenOkHandler(
            expectedPaths:
            [
                "/api/v1/agents/a1/snapshot",
                "/api/v1/agents/a1/probe-results",
                "/api/v1/agents/a1/diagnostic-bundles",
            ],
            okBodies:
            [
                """{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":["identity"]}""",
                """{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":[]}""",
                """{"status":"accepted","bundle_id":"bundle-1","accepted":1,"ignored":0,"reason":null}""",
            ]);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        await client.SubmitSnapshotAsync(
            AgentSnapshotFactory.Create(
                Metadata(),
                DateTimeOffset.Parse("2026-05-07T00:00:00Z"),
                new Dictionary<string, object?> { ["identity"] = new { status = "ok" } }),
            CancellationToken.None);
        await client.SubmitProbeResultAsync(
            AgentTelemetryFactory.CreateProbeResult(
                Metadata(),
                resultId: "res-12345678",
                probeId: "agent.self_test",
                status: "ok",
                payload: new Dictionary<string, object?>()),
            CancellationToken.None);
        await client.SubmitDiagnosticBundleAsync(
            AgentTelemetryFactory.CreateDiagnosticBundle(
                Metadata(),
                clientBundleId: "diag-12345678",
                manifest: new Dictionary<string, object?>(),
                summary: new Dictionary<string, object?>(),
                payload: new Dictionary<string, object?>(),
                collectedAtUtc: DateTimeOffset.Parse("2026-05-07T00:00:00Z")),
            CancellationToken.None);

        Assert.Equal(2, handler.AttemptsByPath["/api/v1/agents/a1/snapshot"]);
        Assert.Equal(2, handler.AttemptsByPath["/api/v1/agents/a1/probe-results"]);
        Assert.Equal(2, handler.AttemptsByPath["/api/v1/agents/a1/diagnostic-bundles"]);
    }

    [Fact]
    public async Task UnsafeTelemetrySubmit_DoesNotRetryEventsCommandResultPreauthOrSelfDeactivate()
    {
        var handler = new AlwaysUnavailableHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitEventsAsync(
            AgentTelemetryFactory.CreateEvents(
                Metadata(),
                new[]
                {
                    new AgentEventItem(
                        EventId: "evt-12345678",
                        Type: "agent.started",
                        OccurredAt: "2026-05-07T00:00:00Z",
                        Severity: "info",
                        Payload: new Dictionary<string, object?>()),
                }),
            CancellationToken.None));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitCommandResultAsync(
            "cmd-1",
            new { status = "DONE" },
            CancellationToken.None));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetTailscalePreauthAsync(CancellationToken.None));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SelfDeactivateAsync(
            new AgentSelfDeactivateRequest(
                SchemaVersion: "agent.self-deactivate.v1",
                ReasonCode: "unit",
                Reason: "unit"),
            CancellationToken.None));

        Assert.Equal(1, handler.AttemptsByPath["/api/v1/agents/a1/events"]);
        Assert.Equal(1, handler.AttemptsByPath["/api/v1/agents/a1/commands/cmd-1/result"]);
        Assert.Equal(1, handler.AttemptsByPath["/api/v1/agents/a1/tailscale/preauth"]);
        Assert.Equal(1, handler.AttemptsByPath["/api/v1/agents/a1/deactivate"]);
    }
}
