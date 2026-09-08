using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateDurabilityTests
{
    [Fact]
    public void InstallerHealthDiagnosticPreservesGuardEvidenceWithoutSensitiveErrorData()
    {
        var error = new System.ComponentModel.Win32Exception(5, @"secret C:\private\credentials.json https://private.invalid/token");
        error.Data["raw_response"] = "must-not-be-recorded";
        foreach (var phase in Enum.GetValues<AgentInstallerHealthPhase>())
        {
            var diagnostic = AgentInstallerHealthDiagnostic.Capture(phase, error, "0.2.144", "0.2.143+build", 41, 42, false);
            var json = JsonSerializer.Serialize(diagnostic, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            using var document = JsonDocument.Parse(json);
            Assert.Equal(new[] { "errorCategory", "exceptionType", "expectedVersion", "nativeErrorCode", "observedVersion", "operation",
                "phase", "pipeProcessId", "recordedAtUtc", "responseSuccess", "schemaVersion", "serviceProcessId" },
                document.RootElement.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
            Assert.Equal("agent.installer.health-diagnostic.v1", diagnostic.SchemaVersion);
            Assert.Equal("health", diagnostic.Operation);
            Assert.Equal(JsonNamingPolicy.SnakeCaseLower.ConvertName(phase.ToString()), diagnostic.Phase);
            Assert.Equal("win32_error", diagnostic.ErrorCategory);
            Assert.Equal("Win32Exception", diagnostic.ExceptionType);
            Assert.Equal(5, diagnostic.NativeErrorCode);
            Assert.Equal("0.2.144", diagnostic.ExpectedVersion);
            Assert.Equal("0.2.143+build", diagnostic.ObservedVersion);
            Assert.Equal((uint)41, diagnostic.ServiceProcessId);
            Assert.Equal((uint)42, diagnostic.PipeProcessId);
            Assert.False(diagnostic.ResponseSuccess);
            Assert.DoesNotContain("secret", json);
            Assert.DoesNotContain("private", json);
            Assert.DoesNotContain("raw_response", json);
            Assert.DoesNotContain("must-not-be-recorded", json);
        }
    }

    [Fact]
    public void InstallerHealthDiagnosticBoundsVersionsAndUnknownErrors()
    {
        var diagnostic = AgentInstallerHealthDiagnostic.Capture(AgentInstallerHealthPhase.ResponseVersion,
            new Exception("private error"), @"C:\private\value", new string('a', 97), null, null, null);
        Assert.Null(diagnostic.ExpectedVersion);
        Assert.Null(diagnostic.ObservedVersion);
        Assert.Null(diagnostic.NativeErrorCode);
        Assert.Equal("unexpected_error", diagnostic.ErrorCategory);
        Assert.Equal("UnexpectedException", diagnostic.ExceptionType);
        Assert.Throws<ArgumentOutOfRangeException>(() => AgentInstallerHealthDiagnostic.Capture(
            (AgentInstallerHealthPhase)int.MaxValue, new Exception(), null, null, null, null, null));
    }

    [Fact]
    public void PublisherIdentity_BindsSpkiNotCertificateSerialOrRenewal()
    {
        using var key = RSA.Create(2048);
        var firstRequest = new CertificateRequest("CN=Publisher A", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var secondRequest = new CertificateRequest("CN=Renewed Publisher", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var first = firstRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var second = secondRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
        Assert.NotEqual(first.Thumbprint, second.Thumbprint);
        Assert.Equal(AgentUpdateAuthenticode.PublisherSpkiSha256(first), AgentUpdateAuthenticode.PublisherSpkiSha256(second));
        Assert.StartsWith("sha256:", AgentUpdateAuthenticode.PublisherSpkiSha256(first));
    }

    [Theory]
    [InlineData("https://releases.example/package/a.msi", true)]
    [InlineData("https://releases.example/package-evil/a.msi", false)]
    [InlineData("https://releases.example.evil/package/a.msi", false)]
    [InlineData("http://releases.example/package/a.msi", false)]
    [InlineData("https://user@releases.example/package/a.msi", false)]
    public void ArtifactPrefix_BindsOriginAndPathSegment(string value, bool allowed)
        => Assert.Equal(allowed, AgentUpdateManifestValidator.IsAllowedArtifactUri(new Uri(value), "https://releases.example/package"));

    [Theory]
    [InlineData(0, AgentUpdateStates.HealthPending)]
    [InlineData(3010, AgentUpdateStates.PendingReboot)]
    [InlineData(1618, AgentUpdateStates.RetryableBusy)]
    [InlineData(1603, AgentUpdateStates.Failed)]
    public void InstallerExitCode_IsNotHealthyInstalledEvidence(int exit, string expected)
        => Assert.Equal(expected, AgentUpdateInstallerResult.FromMsiExitCode(exit, null, null).State);

    [Fact]
    public void CrashAfterInstallerFence_IsUnfinishedAndNeverASecondLaunchPermission()
    {
        foreach (var phase in new[] { "install_may_have_started", AgentUpdateStates.Installing, AgentUpdateStates.RecoveryRequired, AgentUpdateStates.PendingReboot })
        {
            var journal = new AgentUpdateJournal { AttemptId = "attempt1", Phase = phase };
            Assert.True(journal.MayHaveStartedInstallation);
            Assert.True(journal.HasUnfinishedAttempt);
            Assert.False(AgentUpdateStates.CanApply(phase));
        }
        Assert.False(new AgentUpdateJournal { AttemptId = "attempt1", Phase = AgentUpdateStates.Blocked }.HasUnfinishedAttempt);
    }

    [Theory]
    [InlineData(AgentUpdateStates.Checking, null)]
    [InlineData(AgentUpdateStates.Downloading, "synthetic-attempt")]
    [InlineData(AgentUpdateStates.Failed, "synthetic-attempt")]
    public void IntentionalCancellation_RewindsSyntheticPreInstallState(string phase, string? attemptId)
    {
        var root = NewRoot();
        var operationStart = new AgentUpdateJournal
        {
            ScheduleSeed = "cancel-retry",
            Phase = AgentUpdateStates.Current,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-09T00:00:00Z"),
        };
        var current = operationStart with
        {
            Phase = phase,
            AttemptId = attemptId,
            InstallerResult = attemptId is null ? null : AgentUpdateInstallerResult.Failure(new Exception("synthetic")),
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };

        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var transitioned = PersistTransition(root, current, operationStart, retryAt);

        Assert.Equal(AgentUpdateStates.NotChecked, transitioned.Phase);
        Assert.Null(transitioned.AttemptId);
        Assert.Null(transitioned.InstallerResult);
        Assert.Equal(retryAt, transitioned.NextCheckUtc);
        Assert.Null(transitioned.NextRetryUtc);
        Assert.Equal(0, transitioned.RetryCount);
    }

    [Fact]
    public void IntentionalCancellation_PreservesFenceAndTerminalEvidence()
    {
        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        foreach (var phase in new[]
        {
            "launch_requested", "install_may_have_started", AgentUpdateStates.Installing,
            AgentUpdateStates.HealthPending, AgentUpdateStates.PendingReboot, AgentUpdateStates.RecoveryRequired,
        })
        {
            var root = NewRoot();
            var operationStart = new AgentUpdateJournal { ScheduleSeed = "fence-" + phase, Phase = AgentUpdateStates.Current };
            var current = operationStart with
            {
                Phase = phase,
                AttemptId = "active-attempt",
                NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
            };

            var transitioned = PersistTransition(root, current, operationStart, retryAt);

            Assert.Equal(phase == "launch_requested" ? AgentUpdateStates.RecoveryRequired : phase, transitioned.Phase);
            Assert.Equal(current.AttemptId, transitioned.AttemptId);
            Assert.Equal(current.NextCheckUtc, transitioned.NextCheckUtc);
        }

        foreach (var phase in new[] { AgentUpdateStates.Installed, AgentUpdateStates.Blocked, AgentUpdateStates.Quarantined })
        {
            var root = NewRoot();
            var operationStart = new AgentUpdateJournal { ScheduleSeed = "terminal-" + phase, Phase = AgentUpdateStates.Current };
            var current = operationStart with
            {
                Phase = phase,
                AttemptId = "terminal-attempt",
                InstallerResult = AgentUpdateInstallerResult.Failure(new Exception("terminal evidence")),
                NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
            };

            var transitioned = PersistTransition(root, current, operationStart, retryAt);

            Assert.Equal(current.Phase, transitioned.Phase);
            Assert.Equal(current.AttemptId, transitioned.AttemptId);
            Assert.Equal(current.InstallerResult, transitioned.InstallerResult);
            Assert.Equal(current.NextCheckUtc, transitioned.NextCheckUtc);
        }
    }

    [Fact]
    public void IntentionalCancellation_PreservesPriorFailureEvidenceButMakesRetryDue()
    {
        var root = NewRoot();
        var priorResult = new AgentUpdateInstallerResult(
            AgentUpdateInstallerResult.CurrentSchemaVersion, "prior-result", AgentUpdateStates.Failed,
            "2026-09-07T00:00:00Z", 1603, false, AgentUpdateErrorCodes.MsiFailed, "prior failure", null, "prior-attempt");
        var operationStart = new AgentUpdateJournal
        {
            ScheduleSeed = "prior-failure",
            AttemptId = "prior-attempt",
            Phase = AgentUpdateStates.Failed,
            InstallerResult = priorResult,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };
        var current = operationStart with
        {
            Phase = AgentUpdateStates.Failed,
            AttemptId = "synthetic-attempt",
            InstallerResult = AgentUpdateInstallerResult.Failure(new Exception("synthetic failure")),
        };

        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var transitioned = PersistTransition(root, current, operationStart, retryAt);

        Assert.Equal(AgentUpdateStates.Failed, transitioned.Phase);
        Assert.Equal("prior-attempt", transitioned.AttemptId);
        Assert.Equal(priorResult, transitioned.InstallerResult);
        Assert.Equal(retryAt, transitioned.NextCheckUtc);
    }

    [Theory]
    [InlineData(AgentUpdateStates.Failed)]
    [InlineData(AgentUpdateStates.Installed)]
    public void IntentionalCancellation_RestoresPriorOperationMetadata(string priorPhase)
    {
        var root = NewRoot();
        var operationStart = new AgentUpdateJournal
        {
            ScheduleSeed = "prior-metadata-" + priorPhase,
            AttemptId = "prior-attempt",
            Phase = priorPhase,
            Automatic = true,
            Required = true,
            LifecycleGeneration = 41,
            InstallerResult = priorPhase == AgentUpdateStates.Failed
                ? AgentUpdateInstallerResult.Failure(new Exception("prior failure"))
                : null,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };
        var current = operationStart with
        {
            Phase = AgentUpdateStates.Checking,
            Automatic = false,
            Required = false,
            LifecycleGeneration = 99,
            AttemptId = null,
            InstallerResult = null,
        };

        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var transitioned = PersistTransition(root, current, operationStart, retryAt);

        Assert.Equal(priorPhase, transitioned.Phase);
        Assert.Equal(operationStart.AttemptId, transitioned.AttemptId);
        Assert.Equal(operationStart.Automatic, transitioned.Automatic);
        Assert.Equal(operationStart.Required, transitioned.Required);
        Assert.Equal(operationStart.LifecycleGeneration, transitioned.LifecycleGeneration);
        Assert.Equal(operationStart.InstallerResult, transitioned.InstallerResult);
        Assert.Equal(retryAt, transitioned.NextCheckUtc);
    }

    [Theory]
    [InlineData(AgentUpdateStates.AwaitingConsent)]
    [InlineData(AgentUpdateStates.Available)]
    public void IntentionalCancellation_PreservesReadyResultAndMakesRetryDue(string phase)
    {
        var root = NewRoot();
        var operationStart = new AgentUpdateJournal { ScheduleSeed = "ready-" + phase, Phase = AgentUpdateStates.Current };
        var current = operationStart with
        {
            Phase = phase,
            AttemptId = "staged-attempt",
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };

        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var transitioned = PersistTransition(root, current, operationStart, retryAt);

        Assert.Equal(current.Phase, transitioned.Phase);
        Assert.Equal(current.AttemptId, transitioned.AttemptId);
        Assert.Equal(retryAt, transitioned.NextCheckUtc);
    }

    [Fact]
    public void IntentionalCancellation_BlocksRequiredStagedAttemptAndLeavesItDue()
    {
        var root = NewRoot();
        var operationStart = new AgentUpdateJournal { ScheduleSeed = "staged-cancel", Phase = AgentUpdateStates.Current };
        var current = operationStart with
        {
            Phase = AgentUpdateStates.Staged,
            AttemptId = "required-staged-attempt",
            Automatic = true,
            Required = true,
            LifecycleGeneration = 17,
            InstallerResult = AgentUpdateInstallerResult.Failure(new Exception("staging evidence")),
            NextCheckUtc = DateTimeOffset.UtcNow.AddHours(24),
        };

        var retryAt = DateTimeOffset.UtcNow.AddSeconds(-1);
        var transitioned = PersistTransition(root, current, operationStart, retryAt);

        Assert.Equal(AgentUpdateStates.Blocked, transitioned.Phase);
        Assert.Equal(current.AttemptId, transitioned.AttemptId);
        Assert.Equal(current.InstallerResult, transitioned.InstallerResult);
        Assert.Equal(current.Automatic, transitioned.Automatic);
        Assert.Equal(current.Required, transitioned.Required);
        Assert.Equal(current.LifecycleGeneration, transitioned.LifecycleGeneration);
        Assert.False(transitioned.HasUnfinishedAttempt);
        Assert.False(AgentUpdateStates.CanApply(transitioned.Phase));
        Assert.True(transitioned.NextCheckUtc <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public void CancellationClassification_DistinguishesCallerOrLinkedCancellationFromTimeout()
    {
        using var caller = new CancellationTokenSource();
        using var operation = new CancellationTokenSource();
        var timeout = new OperationCanceledException("HTTP timeout");

        Assert.False(AgentUpdateLocalService.IsIntentionalCancellation(
            timeout, caller.Token, operation.Token, authorizationChanged: false));

        caller.Cancel();
        Assert.True(AgentUpdateLocalService.IsIntentionalCancellation(
            timeout, caller.Token, operation.Token, authorizationChanged: false));

        caller.Dispose();
        using var linked = new CancellationTokenSource();
        linked.Cancel();
        Assert.True(AgentUpdateLocalService.IsIntentionalCancellation(
            timeout, CancellationToken.None, linked.Token, authorizationChanged: false));
        Assert.True(AgentUpdateLocalService.IsIntentionalCancellation(
            timeout, CancellationToken.None, CancellationToken.None, authorizationChanged: true));
    }

    [Fact]
    public void TimeoutFailureTransition_RetainsPersistedBackoffAndFailureState()
    {
        var future = DateTimeOffset.Parse("2026-09-10T00:00:00Z");
        var before = new AgentUpdateJournal
        {
            Phase = AgentUpdateStates.Checking,
            NextCheckUtc = future,
            RetryCount = 0,
        };

        var after = AgentUpdateLocalService.TransitionFailure(before);

        Assert.Equal(AgentUpdateStates.Failed, after.Phase);
        Assert.Equal(future, after.NextCheckUtc);
        Assert.Equal(before.RetryCount, after.RetryCount);
        Assert.Null(after.NextRetryUtc);
    }

    [Fact]
    public void DurableJournal_RejectsUnknownPhaseAndPreservesRecord()
    {
        var root = NewRoot();
        var path = Path.Combine(root, "transaction.json");
        AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { Phase = "unrecognized" });
        var before = File.ReadAllBytes(path);
        Assert.Throws<InvalidOperationException>(() => new AgentUpdateJournalStore(root).Read());
        Assert.Equal(before, File.ReadAllBytes(path));
    }

    [Fact]
    public void AcceptedSequence_RequiresExactHighestDigestAndRejectsCorruption()
    {
        var root = NewRoot();
        var path = Path.Combine(root, "highest-sequence.json");
        var digest = new string('a', 64);
        AgentUpdateDurableFile.Write(path, root, new { schema_version = "agent.update.sequence.v2", highest_sequence = 42, manifest_digest = digest });
        AgentUpdateSequenceStore.RequireAccepted(root, 42, digest);
        Assert.Throws<InvalidOperationException>(() => AgentUpdateSequenceStore.RequireAccepted(root, 41, digest));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateSequenceStore.RequireAccepted(root, 42, new string('b', 64)));
        File.WriteAllText(path, "{");
        Assert.Throws<InvalidOperationException>(() => AgentUpdateSequenceStore.ReadHighest(root));
    }

    [Fact]
    public async Task ReportSequence_PersistsAcrossAttemptsAndReusesUnchangedPayload()
    {
        var root = NewRoot();
        var store = new AgentUpdateStateStore(Path.Combine(root, "state.json"), Path.Combine(root, "result.json"));
        var state = AgentUpdateState.NotChecked("1.0.0") with { State = AgentUpdateStates.Staged, AttemptId = "one" };
        await store.WriteAsync(state, CancellationToken.None);
        var first = await store.ReadAsync("1.0.0", CancellationToken.None);
        await store.WriteAsync(first, CancellationToken.None);
        var retry = await store.ReadAsync("1.0.0", CancellationToken.None);
        Assert.Equal(first.ReportSequence, retry.ReportSequence);
        await store.WriteAsync(first with { AttemptId = "two" }, CancellationToken.None);
        var next = await new AgentUpdateStateStore(store.StatePath, store.InstallerResultPath).ReadAsync("1.0.0", CancellationToken.None);
        Assert.Equal(first.ReportSequence + 1, next.ReportSequence);
        Assert.Equal("agent.update.status.v2", next.ToHeartbeatStatus()["schema_version"]);
        Assert.Equal(next.ToHeartbeatStatus(), next.ToCommandResultPayload());
    }

    [Fact]
    public void BootIdentity_IsStableAcrossReadsWithinOneBoot()
    {
        if (!OperatingSystem.IsWindows()) return;
        var first = AgentUpdateBootIdentity.Read();
        Assert.True(Guid.TryParse(first, out _));
        Assert.Equal(first, AgentUpdateBootIdentity.Read());
    }

    [Fact]
    public void V2Manifest_RejectsSignedMissingLengthExpiredAndDuplicateFields()
    {
        using var rsa = RSA.Create(2048);
        var unsigned = new AgentUpdateManifest("msi", "2.0.0", "stable", "https://releases.example/package/a.msi", new string('a', 64),
            "Publisher", DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O"), "agent.heartbeat.v1", false, "",
            AgentUpdateManifest.V2SchemaVersion, 42, DateTimeOffset.UtcNow.AddDays(1).ToString("O"), 100, "sha256:" + new string('b', 64));
        AgentUpdateManifest Sign(AgentUpdateManifest input) => input with { Signature = Convert.ToBase64String(rsa.SignData(Encoding.UTF8.GetBytes(AgentUpdateManifestValidator.CanonicalPayload(input)), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) };
        AgentUpdateManifest Validate(AgentUpdateManifest input) => AgentUpdateManifestValidator.Validate(input, rsa.ExportSubjectPublicKeyInfoPem(), "stable", new[] { "https://releases.example/package/" }, "1.0.0");
        var valid = Sign(unsigned);
        Assert.Equal(valid, Validate(valid));
        Assert.Throws<InvalidOperationException>(() => Validate(Sign(unsigned with { ArtifactLength = null })));
        Assert.Throws<InvalidOperationException>(() => Validate(Sign(unsigned with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(-1).ToString("O") })));
        var json = JsonSerializer.Serialize(valid);
        json = json.Insert(1, "\"sequence\":42,");
        Assert.Throws<InvalidOperationException>(() => AgentUpdateManifestValidator.ParseAndValidateJson(json, rsa.ExportSubjectPublicKeyInfoPem(), "stable", new[] { "https://releases.example/package/" }, "1.0.0"));
    }

    [Fact]
    public void VolumeRootBoundary_AcceptsDescendantWithoutAcceptingSibling()
    {
        var path = Path.GetFullPath(Path.GetTempPath());
        Assert.True(AgentUpdateSecurity.IsUnderDirectory(path, Path.GetPathRoot(path)!));
        Assert.False(AgentUpdateSecurity.IsUnderDirectory(Path.Combine(path, "protected-evil", "a"), Path.Combine(path, "protected")));
    }

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-durability-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }

    private static AgentUpdateJournal PersistTransition(
        string root,
        AgentUpdateJournal current,
        AgentUpdateJournal operationStart,
        DateTimeOffset retryAtUtc)
    {
        var path = Path.Combine(root, "transaction.json");
        AgentUpdateDurableFile.Write(path, root, current);
        var persisted = new AgentUpdateJournalStore(root).Read();
        var transitioned = AgentUpdateLocalService.TransitionIntentionalCancellation(persisted, operationStart, retryAtUtc);
        AgentUpdateDurableFile.Write(path, root, transitioned);
        return new AgentUpdateJournalStore(root).Read();
    }
}
