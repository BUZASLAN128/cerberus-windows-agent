using System.IO.Compression;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.Core;

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

    [Fact]
    public async Task ExportAsync_WithExplicitLogDirectory_CollectsOnlyOverrideAndRedactsContent()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-agent-diagnostics-tests", Guid.NewGuid().ToString("N"));
        var outputDir = Path.Combine(root, "output");
        var selectedLogDir = Path.Combine(root, "selected");
        var ignoredLogDir = Path.Combine(root, "ignored");
        Directory.CreateDirectory(selectedLogDir);
        Directory.CreateDirectory(ignoredLogDir);
        await File.WriteAllTextAsync(Path.Combine(selectedLogDir, "selected.log"), "refresh_token: selected-secret\nsafe status");
        await File.WriteAllTextAsync(Path.Combine(ignoredLogDir, "ignored.log"), "ignored log content");

        try
        {
            var archivePath = await AgentDiagnosticsBundle.ExportAsync(outputDir, selectedLogDir);
            using var archive = ZipFile.OpenRead(archivePath);

            var selected = archive.GetEntry("logs/selected.log");
            Assert.NotNull(selected);
            using var reader = new StreamReader(selected!.Open());
            var content = await reader.ReadToEndAsync();
            Assert.DoesNotContain("selected-secret", content);
            Assert.Contains("[REDACTED]", content);
            Assert.Contains("safe status", content);
            Assert.Null(archive.GetEntry("logs/ignored.log"));
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ExportAsync_DefaultLogCollectionReferencesBothUserAndServiceDirectories()
    {
        var repoRoot = FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Diagnostics", "AgentDiagnosticsBundle.cs"));

        Assert.Contains("AgentFileLogger.UserLogDirectory", source);
        Assert.Contains("AgentFileLogger.ServiceLogDirectory", source);
        Assert.Contains("logDir is null", source);
    }

    [Fact]
    public async Task DiagnosticBundleCollectCommandHandler_UploadsAndReturnsDone()
    {
        AgentDiagnosticRequestContext? captured = null;
        var uploader = new AgentDiagnosticBundleUploader(
            Metadata(),
            (context, _) =>
            {
                captured = context;
                return Task.FromResult(new AgentDiagnosticBundleAckResponse(
                    Status: "accepted",
                    BundleId: "bundle-1",
                    Accepted: 1,
                    Ignored: 0,
                    Reason: null));
            });
        var handler = new DiagnosticBundleCollectCommandHandler(uploader);

        var result = await handler.HandleAsync(
            new AgentCommand(
                Id: "cmd-1",
                Type: AgentDiagnosticBundleUploader.CommandType,
                IdempotencyKey: "idem-1",
                Payload: new
                {
                    source = "manual",
                    requested_by = "operator@example.com",
                    reason = "unit",
                }),
            CancellationToken.None);

        Assert.Equal("DONE", result.Status);
        Assert.Equal(0, result.ExitCode);
        Assert.NotNull(captured);
        Assert.Equal("manual", captured!.Source);
        Assert.Equal("operator@example.com", captured.RequestedBy);
        Assert.Equal("cmd-1", captured.RequestCommandId);
        Assert.Equal("unit", captured.Reason);
    }

    [Fact]
    public async Task DiagnosticBundleScheduler_CreatesInitialFutureStateWithJitter()
    {
        var path = Path.Combine(Path.GetTempPath(), $"cerberus-diag-scheduler-{Guid.NewGuid():N}.json");
        try
        {
            var now = DateTimeOffset.Parse("2026-06-02T00:00:00Z");
            var uploader = new AgentDiagnosticBundleUploader(
                Metadata(),
                (_, _) => Task.FromResult(new AgentDiagnosticBundleAckResponse("accepted", "bundle", 1, 0, null)));
            var scheduler = new DiagnosticBundleScheduler(
                uploader,
                NullAgentLogger.Instance,
                statePath: path,
                interval: TimeSpan.FromDays(7),
                maxJitter: TimeSpan.FromHours(6),
                clock: () => now,
                jitterSeconds: max => Math.Min(max - 1, 60));

            var state = await scheduler.LoadOrCreateStateAsync(CancellationToken.None);

            Assert.Null(state.LastSuccessfulUploadUtc);
            Assert.Equal("2026-06-02T00:01:00.0000000+00:00", state.NextDueUtc);
            Assert.True(File.Exists(path));
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    [Fact]
    public void DiagnosticBundleHandler_IsAdvertisedInCapabilities()
    {
        var cachePath = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json");
        var dispatcher = new CommandDispatcher(
            new ICommandHandler[]
            {
                new DiagnosticBundleCollectCommandHandler(
                    new AgentDiagnosticBundleUploader(
                        Metadata(),
                        (_, _) => Task.FromResult(new AgentDiagnosticBundleAckResponse("accepted", "bundle", 1, 0, null)))),
            },
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));

        Assert.Contains(AgentDiagnosticBundleUploader.CommandType, dispatcher.HandlerTypes);
    }

    private static AgentBuildMetadata Metadata() => new(
        AgentVersion: "1.2.3",
        BuildId: "build-1",
        BuildChannel: "dev",
        BootId: "boot-1",
        SupportedSchemaVersions: AgentSchemaVersions.All);

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "Cerberus.Agent.App")) &&
                Directory.Exists(Path.Combine(dir.FullName, "tests", "Cerberus.Agent.Core.Tests")))
                return dir.FullName;

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate cerberus-windows-agent repository root.");
    }
}
