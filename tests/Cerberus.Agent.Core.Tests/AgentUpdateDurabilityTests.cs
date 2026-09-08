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

    [Theory]
    [InlineData(AgentUpdateStates.Checking)]
    [InlineData(AgentUpdateStates.Downloading)]
    [InlineData(AgentUpdateStates.Staged)]
    [InlineData(AgentUpdateStates.AwaitingConsent)]
    [InlineData(AgentUpdateStates.RetryableBusy)]
    public void ReconciliationFailure_BlocksPreInstallAttemptAndPreservesRequiredEvidence(string phase)
    {
        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var installerResult = AgentUpdateInstallerResult.Failure(new Exception("staged evidence"));
        var current = new AgentUpdateJournal
        {
            AttemptId = "reconcile-attempt",
            Phase = phase,
            Automatic = true,
            Required = false,
            LifecycleGeneration = 41,
            ApplyNotBeforeUtc = DateTimeOffset.Parse("2026-09-09T00:00:00Z"),
            RetryCount = 2,
            NextRetryUtc = DateTimeOffset.Parse("2026-09-09T01:00:00Z"),
            RunnerProcessId = 123,
            RunnerStartedUtc = DateTimeOffset.Parse("2026-09-08T10:00:00Z"),
            InstallerProcessId = 456,
            InstallerStartedUtc = DateTimeOffset.Parse("2026-09-08T10:01:00Z"),
            InstallationBootId = "boot-41",
            InstallerResult = installerResult,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };

        var transitioned = AgentUpdateLocalService.TransitionReconciliationFailure(
            current, retryAt, required: true);

        Assert.Equal(AgentUpdateStates.Blocked, transitioned.Phase);
        Assert.Equal(current.AttemptId, transitioned.AttemptId);
        Assert.Equal(current.Automatic, transitioned.Automatic);
        Assert.True(transitioned.Required);
        Assert.Equal(current.LifecycleGeneration, transitioned.LifecycleGeneration);
        Assert.Equal(current.LifecycleGeneration, transitioned.RequiredPolicyGeneration);
        Assert.Equal(current.RunnerProcessId, transitioned.RunnerProcessId);
        Assert.Equal(current.RunnerStartedUtc, transitioned.RunnerStartedUtc);
        Assert.Equal(current.InstallerProcessId, transitioned.InstallerProcessId);
        Assert.Equal(current.InstallerStartedUtc, transitioned.InstallerStartedUtc);
        Assert.Equal(current.InstallationBootId, transitioned.InstallationBootId);
        Assert.Equal(installerResult, transitioned.InstallerResult);
        Assert.Null(transitioned.ApplyNotBeforeUtc);
        Assert.Null(transitioned.NextRetryUtc);
        Assert.Equal(retryAt, transitioned.NextCheckUtc);
        Assert.False(transitioned.HasUnfinishedAttempt);
        Assert.False(transitioned.MayHaveStartedInstallation);
        Assert.False(AgentUpdateStates.CanApply(transitioned.Phase));

        var preservedRequired = AgentUpdateLocalService.TransitionReconciliationFailure(
            current with { Required = true }, retryAt, required: false);
        Assert.True(preservedRequired.Required);
    }

    [Theory]
    [InlineData("launch_requested")]
    [InlineData("install_may_have_started")]
    [InlineData(AgentUpdateStates.Installing)]
    [InlineData(AgentUpdateStates.HealthPending)]
    [InlineData(AgentUpdateStates.PendingReboot)]
    [InlineData(AgentUpdateStates.RecoveryRequired)]
    [InlineData(AgentUpdateStates.Installed)]
    [InlineData(AgentUpdateStates.Failed)]
    [InlineData(AgentUpdateStates.Blocked)]
    [InlineData(AgentUpdateStates.Quarantined)]
    public void ReconciliationFailure_PreservesLaunchFenceAndTerminalEvidence(string phase)
    {
        var current = new AgentUpdateJournal
        {
            AttemptId = "protected-attempt",
            Phase = phase,
            Automatic = true,
            Required = true,
            LifecycleGeneration = 42,
            ApplyNotBeforeUtc = DateTimeOffset.Parse("2026-09-09T00:00:00Z"),
            RetryCount = 1,
            NextRetryUtc = DateTimeOffset.Parse("2026-09-09T01:00:00Z"),
            InstallerResult = AgentUpdateInstallerResult.Failure(new Exception("terminal evidence")),
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };

        var transitioned = AgentUpdateLocalService.TransitionReconciliationFailure(
            current, DateTimeOffset.Parse("2026-09-08T12:34:56Z"));

        Assert.Equal(current, transitioned);
    }

    [Fact]
    public void ReconciliationDeferred_PreservesDueRequiredRolloutUntilSameIdentityIsVerified()
    {
        var rolloutDue = DateTimeOffset.Parse("2026-09-08T10:00:00Z");
        var priorCheck = DateTimeOffset.Parse("2026-09-10T00:00:00Z");
        var current = new AgentUpdateJournal
        {
            AttemptId = "due-required-attempt",
            Phase = AgentUpdateStates.AwaitingConsent,
            Automatic = true,
            Required = true,
            LifecycleGeneration = 41,
            ApplyNotBeforeUtc = rolloutDue,
            RetryCount = 1,
            NextRetryUtc = null,
            NextCheckUtc = priorCheck,
        };

        var deferred = AgentUpdateLocalService.TransitionReconciliationDeferred(
            current, DateTimeOffset.Parse("2026-09-08T10:05:00Z"));

        Assert.Equal(AgentUpdateStates.Blocked, deferred.Phase);
        Assert.True(deferred.Required);
        Assert.Equal(DateTimeOffset.Parse("2026-09-08T10:05:00Z"), deferred.NextCheckUtc);
        Assert.Equal(current.ApplyNotBeforeUtc, deferred.ApplyNotBeforeUtc);
        Assert.Equal(current.NextRetryUtc, deferred.NextRetryUtc);
        Assert.Equal(current.RetryCount, deferred.RetryCount);
        Assert.NotNull(deferred.ReconciliationSnapshot);
        Assert.Equal(current.Phase, deferred.ReconciliationSnapshot!.Phase);
        Assert.Equal(current.ApplyNotBeforeUtc, deferred.ReconciliationSnapshot.ApplyNotBeforeUtc);
        Assert.Equal(current.NextCheckUtc, deferred.ReconciliationSnapshot.NextCheckUtc);

        var restored = AgentUpdateLocalService.RestoreReconciliationSnapshot(deferred, lifecycleGeneration: 41);

        Assert.Equal(AgentUpdateStates.AwaitingConsent, restored.Phase);
        Assert.True(restored.Required);
        Assert.Equal(41, restored.LifecycleGeneration);
        Assert.Equal(rolloutDue, restored.ApplyNotBeforeUtc);
        Assert.Equal(current.NextCheckUtc, restored.NextCheckUtc);
        Assert.Equal(current.RetryCount, restored.RetryCount);
        Assert.Null(restored.ReconciliationSnapshot);
        Assert.Equal(41, restored.RequiredPolicyGeneration);

        var retired = AgentUpdateLocalService.TransitionReconciliationFailure(
            deferred, DateTimeOffset.Parse("2026-09-08T10:06:00Z"));
        Assert.Equal(AgentUpdateStates.Blocked, retired.Phase);
        Assert.Null(retired.ReconciliationSnapshot);
        Assert.Null(retired.ApplyNotBeforeUtc);
        Assert.Null(retired.NextRetryUtc);
        Assert.Equal(DateTimeOffset.Parse("2026-09-08T10:06:00Z"), retired.NextCheckUtc);
    }

    [Fact]
    public void ReconciliationRestore_CarriesRequiredSignalIntoSameGenerationRollout()
    {
        var current = new AgentUpdateJournal
        {
            ScheduleSeed = "required-on-retry",
            AttemptId = "recommended-retry-attempt",
            Phase = AgentUpdateStates.AwaitingConsent,
            Automatic = true,
            Required = false,
            LifecycleGeneration = 41,
            ApplyNotBeforeUtc = null,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };
        var deferred = AgentUpdateLocalService.TransitionReconciliationDeferred(
            current, DateTimeOffset.Parse("2026-09-08T10:05:00Z"));
        var beforeRestore = DateTimeOffset.UtcNow;

        var restored = AgentUpdateLocalService.RestoreReconciliationSnapshot(
            deferred,
            lifecycleGeneration: 41,
            required: true);

        Assert.Equal(AgentUpdateStates.AwaitingConsent, restored.Phase);
        Assert.True(restored.Required);
        Assert.NotNull(restored.ApplyNotBeforeUtc);
        Assert.True(restored.ApplyNotBeforeUtc >= beforeRestore);
        Assert.True(restored.ApplyNotBeforeUtc <= beforeRestore.AddHours(24).AddSeconds(1));
        Assert.Null(restored.ReconciliationSnapshot);
    }

    [Fact]
    public void ReconciliationRestore_DoesNotMigrateSnapshotAcrossLifecycleGeneration()
    {
        var retryAt = DateTimeOffset.Parse("2026-09-08T10:06:00Z");
        var deferred = new AgentUpdateJournal
        {
            AttemptId = "stale-generation-attempt",
            Phase = AgentUpdateStates.Blocked,
            Automatic = true,
            Required = false,
            LifecycleGeneration = 41,
            ApplyNotBeforeUtc = DateTimeOffset.Parse("2026-09-09T00:00:00Z"),
            RetryCount = 2,
            NextRetryUtc = DateTimeOffset.Parse("2026-09-09T01:00:00Z"),
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
            ReconciliationSnapshot = new AgentUpdateReconciliationSnapshot(
                AgentUpdateStates.AwaitingConsent,
                LifecycleGeneration: 41,
                Automatic: true,
                Required: false,
                ApplyNotBeforeUtc: DateTimeOffset.Parse("2026-09-09T00:00:00Z"),
                RetryCount: 2,
                NextRetryUtc: DateTimeOffset.Parse("2026-09-09T01:00:00Z"),
                NextCheckUtc: DateTimeOffset.Parse("2026-09-10T00:00:00Z")),
        };

        var retired = AgentUpdateLocalService.RestoreReconciliationSnapshot(
            deferred,
            lifecycleGeneration: 42,
            retryAtUtc: retryAt,
            required: true);

        Assert.Equal(AgentUpdateStates.Blocked, retired.Phase);
        Assert.Equal(41, retired.LifecycleGeneration);
        Assert.Equal(deferred.AttemptId, retired.AttemptId);
        Assert.True(retired.Required);
        Assert.Null(retired.ReconciliationSnapshot);
        Assert.Null(retired.ApplyNotBeforeUtc);
        Assert.Null(retired.NextRetryUtc);
        Assert.Equal(retryAt, retired.NextCheckUtc);
        Assert.False(retired.HasUnfinishedAttempt);
        Assert.False(AgentUpdateStates.CanApply(retired.Phase));
    }

    [Fact]
    public void MissingPlanLoadOrRetirement_PersistsDueRetirementAndAllowsFreshStage()
    {
        var root = NewRoot();
        var attemptId = "orphaned-required-attempt";
        var attemptDirectory = CreateDisposableAttemptLayout(root, attemptId);
        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var futureCheck = retryAt.AddDays(1);
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = AgentUpdateStates.Blocked,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
            ApplyNotBeforeUtc = retryAt.AddHours(-1),
            RetryCount = 1,
            NextRetryUtc = retryAt.AddMinutes(5),
            NextCheckUtc = futureCheck,
            ReconciliationSnapshot = new AgentUpdateReconciliationSnapshot(
                Phase: AgentUpdateStates.AwaitingConsent,
                LifecycleGeneration: 41,
                Automatic: true,
                Required: true,
                ApplyNotBeforeUtc: retryAt.AddHours(-1),
                RetryCount: 1,
                NextRetryUtc: retryAt.AddMinutes(5),
                NextCheckUtc: futureCheck),
        };

        var journalPath = Path.Combine(root, "transaction.json");
        AgentUpdateDurableFile.Write(journalPath, root, current);
        var journal = new AgentUpdateJournalStore(root);
        var active = journal.Read();
        Assert.False(File.Exists(Path.Combine(attemptDirectory, AgentUpdateSecurity.PlanFileName)));

        var plan = AgentUpdateLocalService.LoadOrRetireMissingPlan(
            root,
            active,
            required: false,
            requiredPolicyGeneration: null,
            retryAtUtc: retryAt,
            changeAttempt: DisposableJournalWriter(root));

        Assert.Null(plan);
        var retired = journal.Read();

        Assert.Equal(AgentUpdateStates.Blocked, retired.Phase);
        Assert.Equal(current.AttemptId, retired.AttemptId);
        Assert.True(retired.Required);
        Assert.Equal(41, retired.RequiredPolicyGeneration);
        Assert.Null(retired.ReconciliationSnapshot);
        Assert.Null(retired.ApplyNotBeforeUtc);
        Assert.Null(retired.NextRetryUtc);
        Assert.Equal(retryAt, retired.NextCheckUtc);
        Assert.False(retired.HasUnfinishedAttempt);
        Assert.Equal(current.Revision + 1, retired.Revision);

        var freshStage = AgentUpdateLocalService.TransitionStageStart(
            retired,
            automatic: true,
            required: AgentUpdateLocalService.CarryRequiredBlockedIntent(
                retired,
                required: false,
                lifecycleGeneration: 41),
            lifecycleGeneration: 41,
            nextCheckUtc: futureCheck);
        Assert.Equal(AgentUpdateStates.Checking, freshStage.Phase);
        Assert.True(freshStage.Required);
        Assert.Equal(41, freshStage.RequiredPolicyGeneration);
        Assert.Null(freshStage.ReconciliationSnapshot);
    }

    [Fact]
    public void MissingPlanLoadOrRetirement_CoversDownloadingAndStaleGeneration()
    {
        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");

        var downloadingRoot = NewRoot();
        var downloadingAttempt = "orphaned-downloading-attempt";
        var downloadingDirectory = CreateDisposableAttemptLayout(downloadingRoot, downloadingAttempt);
        var downloading = new AgentUpdateJournal
        {
            AttemptId = downloadingAttempt,
            Phase = AgentUpdateStates.Downloading,
            LifecycleGeneration = 41,
            NextRetryUtc = retryAt.AddMinutes(5),
            NextCheckUtc = retryAt.AddDays(1),
        };
        AgentUpdateDurableFile.Write(Path.Combine(downloadingRoot, "transaction.json"), downloadingRoot, downloading);
        var downloadingJournal = new AgentUpdateJournalStore(downloadingRoot);
        Assert.False(File.Exists(Path.Combine(downloadingDirectory, AgentUpdateSecurity.PlanFileName)));

        Assert.Null(AgentUpdateLocalService.LoadOrRetireMissingPlan(
            downloadingRoot,
            downloadingJournal.Read(),
            required: true,
            requiredPolicyGeneration: 41,
            retryAtUtc: retryAt,
            changeAttempt: DisposableJournalWriter(downloadingRoot)));
        var downloadingRetired = downloadingJournal.Read();

        Assert.Equal(AgentUpdateStates.Blocked, downloadingRetired.Phase);
        Assert.True(downloadingRetired.Required);
        Assert.Equal(41, downloadingRetired.RequiredPolicyGeneration);
        Assert.Null(downloadingRetired.ReconciliationSnapshot);
        Assert.Null(downloadingRetired.NextRetryUtc);
        Assert.Equal(retryAt, downloadingRetired.NextCheckUtc);
        Assert.False(downloadingRetired.HasUnfinishedAttempt);

        var staleRoot = NewRoot();
        var staleAttempt = "orphaned-stale-snapshot";
        var staleDirectory = CreateDisposableAttemptLayout(staleRoot, staleAttempt);
        var stale = new AgentUpdateJournal
        {
            AttemptId = staleAttempt,
            Phase = AgentUpdateStates.Blocked,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = null,
            ApplyNotBeforeUtc = retryAt.AddHours(-1),
            RetryCount = 1,
            NextRetryUtc = retryAt.AddMinutes(5),
            NextCheckUtc = retryAt.AddDays(1),
            ReconciliationSnapshot = new AgentUpdateReconciliationSnapshot(
                Phase: AgentUpdateStates.AwaitingConsent,
                LifecycleGeneration: 40,
                Automatic: true,
                Required: true,
                ApplyNotBeforeUtc: retryAt.AddHours(-1),
                RetryCount: 1,
                NextRetryUtc: retryAt.AddMinutes(5),
                NextCheckUtc: retryAt.AddDays(1)),
        };
        AgentUpdateDurableFile.Write(Path.Combine(staleRoot, "transaction.json"), staleRoot, stale);
        var staleJournal = new AgentUpdateJournalStore(staleRoot);
        Assert.False(File.Exists(Path.Combine(staleDirectory, AgentUpdateSecurity.PlanFileName)));

        Assert.Null(AgentUpdateLocalService.LoadOrRetireMissingPlan(
            staleRoot,
            staleJournal.Read(),
            required: true,
            requiredPolicyGeneration: 42,
            retryAtUtc: retryAt,
            changeAttempt: DisposableJournalWriter(staleRoot)));
        var staleRetired = staleJournal.Read();

        Assert.Equal(AgentUpdateStates.Blocked, staleRetired.Phase);
        Assert.Equal(41, staleRetired.LifecycleGeneration);
        Assert.Equal(42, staleRetired.RequiredPolicyGeneration);
        Assert.Null(staleRetired.ReconciliationSnapshot);
        Assert.Null(staleRetired.ApplyNotBeforeUtc);
        Assert.Null(staleRetired.NextRetryUtc);
        Assert.Equal(retryAt, staleRetired.NextCheckUtc);
        Assert.True(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            staleRetired,
            required: false,
            lifecycleGeneration: 42));
    }

    [Theory]
    [InlineData(AgentUpdateStates.Downloading)]
    [InlineData("launch_requested")]
    [InlineData(AgentUpdateStates.Installing)]
    [InlineData(AgentUpdateStates.RecoveryRequired)]
    public void ExistingPlanLoadOrRetirement_ReturnsPlanWithoutMutatingJournal(string phase)
    {
        var root = NewRoot();
        var attemptId = "planned-attempt-" + phase;
        var attemptDirectory = CreateDisposableAttemptLayout(root, attemptId);
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = phase,
            LifecycleGeneration = 41,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };
        var plan = new AgentUpdatePlan(
            ArtifactKind: "msi",
            Version: "2.0.0",
            Channel: "stable",
            ArtifactPath: Path.Combine(attemptDirectory, AgentUpdateSecurity.ArtifactFileName),
            Sha256: new string('a', 64),
            StagedAtUtc: "2026-09-08T10:00:00Z",
            Reason: "existing-plan",
            AttemptId: attemptId,
            Sequence: 7,
            ManifestDigest: new string('b', 64));

        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, current);
        AgentUpdateDurableFile.Write(
            Path.Combine(attemptDirectory, AgentUpdateSecurity.PlanFileName),
            attemptDirectory,
            plan);
        var journal = new AgentUpdateJournalStore(root);
        var before = journal.Read();

        var result = AgentUpdateLocalService.LoadOrRetireMissingPlan(
            root,
            before,
            required: false,
            requiredPolicyGeneration: null,
            retryAtUtc: DateTimeOffset.Parse("2026-09-08T12:34:56Z"),
            changeAttempt: DisposableJournalWriter(root));

        Assert.Equal(plan, result);
        Assert.Equal(before, journal.Read());
    }

    [Fact]
    public void MissingPlanLoadOrRetirement_PropagatesCorruptPlanWithoutRetirement()
    {
        var root = NewRoot();
        var attemptId = "corrupt-plan-attempt";
        var attemptDirectory = CreateDisposableAttemptLayout(root, attemptId);
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = AgentUpdateStates.Downloading,
            LifecycleGeneration = 41,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, current);
        var journal = new AgentUpdateJournalStore(root);
        File.WriteAllText(Path.Combine(attemptDirectory, AgentUpdateSecurity.PlanFileName), "{");

        var error = Assert.Throws<InvalidOperationException>(() => AgentUpdateLocalService.LoadOrRetireMissingPlan(
            root,
            journal.Read(),
            required: false,
            requiredPolicyGeneration: null,
            retryAtUtc: DateTimeOffset.Parse("2026-09-08T12:34:56Z"),
            changeAttempt: DisposableJournalWriter(root)));

        Assert.Contains("corrupt", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(current, journal.Read());
    }

    [Theory]
    [InlineData("launch_requested")]
    [InlineData(AgentUpdateStates.Installing)]
    [InlineData(AgentUpdateStates.RecoveryRequired)]
    public void MissingPlanLoadOrRetirement_ProtectsLaunchFence(string phase)
    {
        var root = NewRoot();
        var attemptId = "protected-missing-plan-" + phase;
        CreateDisposableAttemptLayout(root, attemptId);
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = phase,
            LifecycleGeneration = 41,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, current);
        var journal = new AgentUpdateJournalStore(root);

        var error = Assert.Throws<InvalidOperationException>(() => AgentUpdateLocalService.LoadOrRetireMissingPlan(
            root,
            journal.Read(),
            required: true,
            requiredPolicyGeneration: 41,
            retryAtUtc: DateTimeOffset.Parse("2026-09-08T12:34:56Z"),
            changeAttempt: DisposableJournalWriter(root)));

        Assert.Equal("Active update plan is missing.", error.Message);
        Assert.Equal(current, journal.Read());
    }

    [Fact]
    public void MissingPlanLoadOrRetirement_ProtectsConcurrentFenceTransition()
    {
        var root = NewRoot();
        var attemptId = "racing-protected-attempt";
        CreateDisposableAttemptLayout(root, attemptId);
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = AgentUpdateStates.Blocked,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
            ReconciliationSnapshot = new AgentUpdateReconciliationSnapshot(
                Phase: AgentUpdateStates.AwaitingConsent,
                LifecycleGeneration: 41,
                Automatic: true,
                Required: true,
                ApplyNotBeforeUtc: DateTimeOffset.UtcNow,
                RetryCount: 1,
                NextRetryUtc: DateTimeOffset.UtcNow.AddMinutes(5),
                NextCheckUtc: DateTimeOffset.UtcNow.AddHours(1)),
        };
        var transactionPath = Path.Combine(root, "transaction.json");
        AgentUpdateDurableFile.Write(transactionPath, root, current);
        var journal = new AgentUpdateJournalStore(root);

        // Unit/support race writer: it models the canonical attempt-ID compare
        // and durable roundtrip, not protected-root locking or ACL acceptance.
        AgentUpdateJournal RaceWriter(
            string requestedAttemptId,
            Func<AgentUpdateJournal, AgentUpdateJournal> transition)
        {
            var before = journal.Read();
            if (!string.Equals(before.AttemptId, requestedAttemptId, StringComparison.Ordinal))
                throw new InvalidOperationException("Update attempt is no longer active.");
            var protectedBefore = before with { Phase = AgentUpdateStates.RecoveryRequired };
            AgentUpdateDurableFile.Write(transactionPath, root, protectedBefore);
            var committedBefore = journal.Read();
            var after = transition(committedBefore) with { Revision = checked(committedBefore.Revision + 1) };
            AgentUpdateDurableFile.Write(transactionPath, root, after);
            return journal.Read();
        }

        var error = Assert.Throws<InvalidOperationException>(() => AgentUpdateLocalService.LoadOrRetireMissingPlan(
            root,
            journal.Read(),
            required: false,
            requiredPolicyGeneration: null,
            retryAtUtc: DateTimeOffset.Parse("2026-09-08T12:34:56Z"),
            changeAttempt: RaceWriter));

        Assert.Equal("Active update plan is missing.", error.Message);
        var persisted = journal.Read();
        Assert.Equal(AgentUpdateStates.RecoveryRequired, persisted.Phase);
        Assert.True(persisted.MayHaveStartedInstallation);
        Assert.NotNull(persisted.ReconciliationSnapshot);
    }

    [Theory]
    [InlineData(AgentUpdateStates.Downloading)]
    [InlineData(AgentUpdateStates.Blocked)]
    [InlineData(AgentUpdateStates.Staged)]
    [InlineData(AgentUpdateStates.AwaitingConsent)]
    [InlineData(AgentUpdateStates.RetryableBusy)]
    public void RecoveryDispatcher_RetiresMissingPreInstallBeforeNormalRouting(string phase)
    {
        var root = NewRoot();
        var attemptId = "dispatcher-missing-" + phase;
        CreateDisposableAttemptLayout(root, attemptId);
        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = phase,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
            ApplyNotBeforeUtc = phase is AgentUpdateStates.AwaitingConsent or AgentUpdateStates.Staged
                ? retryAt.AddHours(-1)
                : null,
            RetryCount = phase is AgentUpdateStates.AwaitingConsent or AgentUpdateStates.Staged ? 1 : 0,
            NextRetryUtc = phase is AgentUpdateStates.AwaitingConsent or AgentUpdateStates.RetryableBusy
                ? retryAt.AddMinutes(5)
                : null,
            NextCheckUtc = retryAt.AddDays(1),
            ReconciliationSnapshot = phase == AgentUpdateStates.Blocked
                ? new AgentUpdateReconciliationSnapshot(
                    Phase: AgentUpdateStates.AwaitingConsent,
                    LifecycleGeneration: 41,
                    Automatic: true,
                    Required: true,
                    ApplyNotBeforeUtc: retryAt.AddHours(-1),
                    RetryCount: 1,
                    NextRetryUtc: retryAt.AddMinutes(5),
                    NextCheckUtc: retryAt.AddDays(1))
                : null,
        };
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, current);
        var journal = new AgentUpdateJournalStore(root);

        var recovered = AgentUpdateLocalService.RecoverActiveAttempt(
            root,
            journal.Read(),
            lifecycleGeneration: 41,
            retryAtUtc: retryAt,
            required: false,
            requiredPolicyGeneration: null,
            change: DisposableJournalChange(root),
            changeAttempt: DisposableJournalWriter(root),
            read: journal.Read);

        Assert.Equal(AgentUpdateStates.Blocked, recovered.Phase);
        Assert.Equal(attemptId, recovered.AttemptId);
        Assert.True(recovered.Required);
        Assert.Equal(41, recovered.RequiredPolicyGeneration);
        Assert.Null(recovered.ReconciliationSnapshot);
        Assert.Null(recovered.ApplyNotBeforeUtc);
        Assert.Null(recovered.NextRetryUtc);
        Assert.Equal(retryAt, recovered.NextCheckUtc);
        Assert.False(recovered.HasUnfinishedAttempt);
        Assert.Equal(recovered, journal.Read());

        var freshStage = AgentUpdateLocalService.TransitionStageStart(
            recovered,
            automatic: true,
            required: AgentUpdateLocalService.CarryRequiredBlockedIntent(
                recovered,
                required: false,
                lifecycleGeneration: 41),
            lifecycleGeneration: 41,
            nextCheckUtc: retryAt);
        Assert.Equal(AgentUpdateStates.Checking, freshStage.Phase);
        Assert.True(freshStage.Required);
        Assert.Equal(41, freshStage.RequiredPolicyGeneration);
    }

    [Theory]
    [InlineData(41, true)]
    [InlineData(42, false)]
    public void RecoveryDispatcher_RecoversInterruptedCheckingWithoutAttempt(int lifecycleGeneration, bool requiredAfterRecovery)
    {
        var root = NewRoot();
        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var current = new AgentUpdateJournal
        {
            Phase = AgentUpdateStates.Checking,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
            ApplyNotBeforeUtc = retryAt.AddHours(-1),
            RetryCount = 1,
            NextRetryUtc = retryAt.AddMinutes(5),
            NextCheckUtc = retryAt.AddDays(1),
        };
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, current);
        var journal = new AgentUpdateJournalStore(root);

        var recovered = AgentUpdateLocalService.RecoverActiveAttempt(
            root,
            journal.Read(),
            lifecycleGeneration,
            retryAt,
            required: false,
            requiredPolicyGeneration: null,
            change: DisposableJournalChange(root),
            changeAttempt: DisposableJournalWriter(root),
            read: journal.Read);

        Assert.Equal(AgentUpdateStates.NotChecked, recovered.Phase);
        Assert.Null(recovered.AttemptId);
        Assert.Equal(lifecycleGeneration, recovered.LifecycleGeneration);
        Assert.Equal(requiredAfterRecovery, recovered.Required);
        Assert.Equal(requiredAfterRecovery ? lifecycleGeneration : null, recovered.RequiredPolicyGeneration);
        Assert.Null(recovered.ReconciliationSnapshot);
        Assert.Null(recovered.ApplyNotBeforeUtc);
        Assert.Null(recovered.NextRetryUtc);
        Assert.Equal(retryAt, recovered.NextCheckUtc);
        Assert.Equal(recovered, journal.Read());
        Assert.Equal(requiredAfterRecovery, AgentUpdateLocalService.CarryRequiredBlockedIntent(
            recovered,
            required: false,
            lifecycleGeneration: lifecycleGeneration));
    }

    [Theory]
    [InlineData(AgentUpdateStates.Downloading)]
    [InlineData(AgentUpdateStates.Staged)]
    [InlineData(AgentUpdateStates.AwaitingConsent)]
    [InlineData(AgentUpdateStates.RetryableBusy)]
    public void RecoveryDispatcher_UsesValidPlanOnlyForStablePreInstallRouting(string phase)
    {
        var root = NewRoot();
        var attemptId = "dispatcher-planned-" + phase;
        var attemptDirectory = CreateDisposableAttemptLayout(root, attemptId);
        var required = phase is AgentUpdateStates.Downloading or AgentUpdateStates.Staged;
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = phase,
            Required = required,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = required ? 41 : null,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };
        var plan = new AgentUpdatePlan(
            ArtifactKind: "msi",
            Version: "2.0.0",
            Channel: "stable",
            ArtifactPath: Path.Combine(attemptDirectory, AgentUpdateSecurity.ArtifactFileName),
            Sha256: new string('a', 64),
            StagedAtUtc: "2026-09-08T10:00:00Z",
            Reason: "dispatcher-plan",
            AttemptId: attemptId,
            Sequence: 7,
            ManifestDigest: new string('b', 64));
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, current);
        AgentUpdateDurableFile.Write(
            Path.Combine(attemptDirectory, AgentUpdateSecurity.PlanFileName),
            attemptDirectory,
            plan);
        var journal = new AgentUpdateJournalStore(root);

        var recovered = AgentUpdateLocalService.RecoverActiveAttempt(
            root,
            journal.Read(),
            lifecycleGeneration: 41,
            retryAtUtc: DateTimeOffset.Parse("2026-09-08T12:34:56Z"),
            required: required,
            requiredPolicyGeneration: required ? 41 : null,
            change: DisposableJournalChange(root),
            changeAttempt: DisposableJournalWriter(root),
            read: journal.Read);

        if (phase is AgentUpdateStates.Downloading or AgentUpdateStates.Staged)
        {
            Assert.Equal(AgentUpdateStates.Blocked, recovered.Phase);
            Assert.True(recovered.Required);
            Assert.Equal(41, recovered.RequiredPolicyGeneration);
            Assert.Null(recovered.ReconciliationSnapshot);
            Assert.Equal(DateTimeOffset.Parse("2026-09-08T12:34:56Z"), recovered.NextCheckUtc);
            Assert.True(File.Exists(Path.Combine(attemptDirectory, AgentUpdateSecurity.PlanFileName)));
        }
        else
        {
            Assert.Equal(current, recovered);
            Assert.Equal(current, journal.Read());
        }
    }

    [Theory]
    [InlineData("launch_requested")]
    [InlineData(AgentUpdateStates.Installing)]
    [InlineData(AgentUpdateStates.RecoveryRequired)]
    [InlineData(AgentUpdateStates.Installed)]
    [InlineData(AgentUpdateStates.Failed)]
    [InlineData(AgentUpdateStates.Quarantined)]
    public void RecoveryDispatcher_LeavesProtectedAndTerminalNonCandidatesUntouched(string phase)
    {
        var root = NewRoot();
        var attemptId = "dispatcher-noncandidate-" + phase;
        CreateDisposableAttemptLayout(root, attemptId);
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = phase,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, current);
        var journal = new AgentUpdateJournalStore(root);

        var recovered = AgentUpdateLocalService.RecoverActiveAttempt(
            root,
            journal.Read(),
            lifecycleGeneration: 41,
            retryAtUtc: DateTimeOffset.Parse("2026-09-08T12:34:56Z"),
            required: false,
            requiredPolicyGeneration: null,
            change: DisposableJournalChange(root),
            changeAttempt: DisposableJournalWriter(root),
            read: journal.Read);

        Assert.Equal(current, recovered);
        Assert.Equal(current, journal.Read());
    }

    [Fact]
    public void RecoveryDispatcher_PropagatesCorruptPlanWithoutRetirement()
    {
        var root = NewRoot();
        var attemptId = "dispatcher-corrupt-plan";
        var attemptDirectory = CreateDisposableAttemptLayout(root, attemptId);
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = AgentUpdateStates.Staged,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
            NextCheckUtc = DateTimeOffset.Parse("2026-09-10T00:00:00Z"),
        };
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, current);
        File.WriteAllText(Path.Combine(attemptDirectory, AgentUpdateSecurity.PlanFileName), "{");
        var journal = new AgentUpdateJournalStore(root);

        var error = Assert.Throws<InvalidOperationException>(() => AgentUpdateLocalService.RecoverActiveAttempt(
            root,
            journal.Read(),
            lifecycleGeneration: 41,
            retryAtUtc: DateTimeOffset.Parse("2026-09-08T12:34:56Z"),
            required: false,
            requiredPolicyGeneration: null,
            change: DisposableJournalChange(root),
            changeAttempt: DisposableJournalWriter(root),
            read: journal.Read));

        Assert.Contains("corrupt", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(current, journal.Read());
    }

    [Fact]
    public void RecoveryDispatcher_ProtectsConcurrentFenceTransition()
    {
        var root = NewRoot();
        var attemptId = "dispatcher-racing-protected";
        CreateDisposableAttemptLayout(root, attemptId);
        var current = new AgentUpdateJournal
        {
            AttemptId = attemptId,
            Phase = AgentUpdateStates.Blocked,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
            ReconciliationSnapshot = new AgentUpdateReconciliationSnapshot(
                Phase: AgentUpdateStates.AwaitingConsent,
                LifecycleGeneration: 41,
                Automatic: true,
                Required: true,
                ApplyNotBeforeUtc: DateTimeOffset.UtcNow,
                RetryCount: 1,
                NextRetryUtc: DateTimeOffset.UtcNow.AddMinutes(5),
                NextCheckUtc: DateTimeOffset.UtcNow.AddHours(1)),
        };
        var transactionPath = Path.Combine(root, "transaction.json");
        AgentUpdateDurableFile.Write(transactionPath, root, current);
        var journal = new AgentUpdateJournalStore(root);

        // Unit/support race writer: it models the canonical attempt-ID compare
        // and durable roundtrip, not protected-root locking or ACL acceptance.
        AgentUpdateJournal RaceWriter(
            string requestedAttemptId,
            Func<AgentUpdateJournal, AgentUpdateJournal> transition)
        {
            var before = journal.Read();
            if (!string.Equals(before.AttemptId, requestedAttemptId, StringComparison.Ordinal))
                throw new InvalidOperationException("Update attempt is no longer active.");
            var protectedBefore = before with { Phase = AgentUpdateStates.RecoveryRequired };
            AgentUpdateDurableFile.Write(transactionPath, root, protectedBefore);
            var committedBefore = journal.Read();
            var after = transition(committedBefore) with { Revision = checked(committedBefore.Revision + 1) };
            AgentUpdateDurableFile.Write(transactionPath, root, after);
            return journal.Read();
        }

        var error = Assert.Throws<InvalidOperationException>(() => AgentUpdateLocalService.RecoverActiveAttempt(
            root,
            journal.Read(),
            lifecycleGeneration: 41,
            retryAtUtc: DateTimeOffset.Parse("2026-09-08T12:34:56Z"),
            required: false,
            requiredPolicyGeneration: null,
            change: DisposableJournalChange(root),
            changeAttempt: RaceWriter,
            read: journal.Read));

        Assert.Equal("Active update plan is missing.", error.Message);
        var persisted = journal.Read();
        Assert.Equal(AgentUpdateStates.RecoveryRequired, persisted.Phase);
        Assert.True(persisted.MayHaveStartedInstallation);
        Assert.NotNull(persisted.ReconciliationSnapshot);
    }

    [Fact]
    public void ScheduledRetry_CarriesRequiredIntentOnlyFromBlockedAttempt()
    {
        var blockedRequired = new AgentUpdateJournal
        {
            AttemptId = "blocked-required-attempt",
            Phase = AgentUpdateStates.Blocked,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
        };
        Assert.True(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            blockedRequired, required: false, lifecycleGeneration: 41));

        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            blockedRequired with { Required = false, RequiredPolicyGeneration = null },
            required: false,
            lifecycleGeneration: 41));
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            blockedRequired with { AttemptId = null }, required: false, lifecycleGeneration: 41));
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            blockedRequired with { Phase = AgentUpdateStates.Failed }, required: false, lifecycleGeneration: 41));
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            blockedRequired, required: false, lifecycleGeneration: 42));
        Assert.True(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            blockedRequired, required: true, lifecycleGeneration: 42));
    }

    [Fact]
    public void RequiredProvenance_SurvivesCheckOnlyAvailableIntoFreshStageSameGeneration()
    {
        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var dailyNextCheck = retryAt.AddDays(1);
        var retired = AgentUpdateLocalService.TransitionReconciliationFailure(
            new AgentUpdateJournal
            {
                AttemptId = "required-old-release",
                Phase = AgentUpdateStates.AwaitingConsent,
                Required = true,
                LifecycleGeneration = 41,
                ApplyNotBeforeUtc = retryAt,
                NextCheckUtc = dailyNextCheck,
            },
            retryAt);

        var requiredForCheck = AgentUpdateLocalService.CarryRequiredBlockedIntent(
            retired, required: false, lifecycleGeneration: 41);
        Assert.True(requiredForCheck);

        var checking = AgentUpdateLocalService.TransitionCheckStart(
            retired,
            automatic: true,
            required: requiredForCheck,
            lifecycleGeneration: 41,
            nextCheckUtc: dailyNextCheck);
        Assert.Equal(AgentUpdateStates.Checking, checking.Phase);
        Assert.Null(checking.AttemptId);
        Assert.True(checking.Required);
        Assert.Equal(41, checking.RequiredPolicyGeneration);

        var available = AgentUpdateLocalService.TransitionCheckResult(
            checking,
            available: true,
            required: AgentUpdateLocalService.CarryRequiredBlockedIntent(
                checking, required: false, lifecycleGeneration: 41),
            lifecycleGeneration: 41,
            now: retryAt);
        Assert.Equal(AgentUpdateStates.Available, available.Phase);
        Assert.Null(available.AttemptId);
        Assert.True(available.Required);
        Assert.Equal(41, available.RequiredPolicyGeneration);
        Assert.Equal(retryAt, available.NextCheckUtc);
        Assert.True(!available.HasUnfinishedAttempt && available.NextCheckUtc <= retryAt);

        var recommendedChecking = AgentUpdateLocalService.TransitionCheckStart(
            retired with { Required = false, RequiredPolicyGeneration = null },
            automatic: true,
            required: false,
            lifecycleGeneration: 41,
            nextCheckUtc: dailyNextCheck);
        var recommendedAvailable = AgentUpdateLocalService.TransitionCheckResult(
            recommendedChecking,
            available: true,
            required: false,
            lifecycleGeneration: 41,
            now: retryAt);
        Assert.Equal(dailyNextCheck, recommendedAvailable.NextCheckUtc);

        var requiredUnavailable = AgentUpdateLocalService.TransitionCheckResult(
            recommendedChecking,
            available: false,
            required: true,
            lifecycleGeneration: 41,
            now: retryAt);
        Assert.Equal(dailyNextCheck, requiredUnavailable.NextCheckUtc);

        var requiredForStage = AgentUpdateLocalService.CarryRequiredBlockedIntent(
            available, required: false, lifecycleGeneration: 41);
        Assert.True(requiredForStage);
        var staging = AgentUpdateLocalService.TransitionStageStart(
            available,
            automatic: true,
            required: requiredForStage,
            lifecycleGeneration: 41,
            nextCheckUtc: retryAt);
        Assert.Equal(AgentUpdateStates.Checking, staging.Phase);
        Assert.True(staging.Required);
        Assert.Equal(41, staging.RequiredPolicyGeneration);

        var plan = new AgentUpdatePlan(
            ArtifactKind: "msi",
            Version: "2.0.0",
            Channel: "stable",
            ArtifactPath: "C:\\staged\\agent.msi",
            Sha256: new string('a', 64),
            StagedAtUtc: retryAt.ToString("O"),
            Reason: "required_retry",
            AttemptId: "fresh-required-attempt",
            Sequence: 2);
        var staged = AgentUpdateLocalService.TransitionStageResult(
            staging with { AttemptId = plan.AttemptId },
            plan,
            automatic: true,
            required: requiredForStage,
            lifecycleGeneration: 41,
            now: retryAt);
        Assert.Equal(AgentUpdateStates.AwaitingConsent, staged.Phase);
        Assert.True(staged.Required);
        Assert.Equal(41, staged.RequiredPolicyGeneration);
        Assert.NotNull(staged.ApplyNotBeforeUtc);
    }

    [Fact]
    public void RequiredProvenance_DoesNotCrossReenrollmentOrTerminalHistory()
    {
        var oldGeneration = new AgentUpdateJournal
        {
            AttemptId = "old-required-attempt",
            Phase = AgentUpdateStates.Blocked,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
        };

        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            oldGeneration, required: false, lifecycleGeneration: 42));
        var freshRecommended = AgentUpdateLocalService.TransitionStageStart(
            oldGeneration,
            automatic: true,
            required: AgentUpdateLocalService.CarryRequiredBlockedIntent(
                oldGeneration, required: false, lifecycleGeneration: 42),
            lifecycleGeneration: 42,
            nextCheckUtc: DateTimeOffset.UtcNow);
        Assert.False(freshRecommended.Required);
        Assert.Null(freshRecommended.RequiredPolicyGeneration);
        Assert.False(AgentUpdateStates.CanApply(freshRecommended.Phase));

        var historicalFailure = new AgentUpdateJournal
        {
            AttemptId = "historical-failure",
            Phase = AgentUpdateStates.Failed,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = null,
        };
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            historicalFailure, required: false, lifecycleGeneration: 41));
    }

    [Fact]
    public void RequiredProvenance_CarriesIncomingGenerationWithoutRebindingRetiredAttempt()
    {
        var retryAt = DateTimeOffset.Parse("2026-09-08T12:34:56Z");
        var current = new AgentUpdateJournal
        {
            AttemptId = "old-recommended-attempt",
            Phase = AgentUpdateStates.AwaitingConsent,
            Required = false,
            LifecycleGeneration = 41,
            ApplyNotBeforeUtc = DateTimeOffset.Parse("2026-09-09T00:00:00Z"),
            ReconciliationSnapshot = null,
        };

        var deferred = AgentUpdateLocalService.TransitionReconciliationDeferred(
            current,
            retryAt,
            required: true,
            requiredPolicyGeneration: 42);

        Assert.Equal(AgentUpdateStates.Blocked, deferred.Phase);
        Assert.True(deferred.Required);
        Assert.Equal(42, deferred.RequiredPolicyGeneration);
        Assert.Equal(41, deferred.LifecycleGeneration);
        Assert.NotNull(deferred.ReconciliationSnapshot);
        Assert.Equal(41, deferred.ReconciliationSnapshot!.LifecycleGeneration);

        // A later recommended retry must retain the newer signal provenance;
        // it must not replace it with the retired attempt's generation.
        var retired = AgentUpdateLocalService.TransitionReconciliationFailure(
            deferred,
            retryAt.AddMinutes(5),
            required: false,
            requiredPolicyGeneration: 41);

        Assert.Equal(42, retired.RequiredPolicyGeneration);
        Assert.Equal(41, retired.LifecycleGeneration);
        Assert.Null(retired.ReconciliationSnapshot);
        Assert.True(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            retired,
            required: false,
            lifecycleGeneration: 42));
    }

    [Fact]
    public void LegacyRequiredBlockedIntent_UsesSameGenerationOnly()
    {
        var legacy = new AgentUpdateJournal
        {
            AttemptId = "legacy-required-attempt",
            Phase = AgentUpdateStates.Blocked,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = null,
        };

        Assert.True(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            legacy,
            required: false,
            lifecycleGeneration: 41));
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            legacy,
            required: false,
            lifecycleGeneration: 42));
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            legacy with { AttemptId = null },
            required: false,
            lifecycleGeneration: 41));
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            legacy with { Phase = AgentUpdateStates.Failed },
            required: false,
            lifecycleGeneration: 41));

        var upgraded = AgentUpdateLocalService.TransitionStageStart(
            legacy,
            automatic: true,
            required: true,
            lifecycleGeneration: 41,
            nextCheckUtc: DateTimeOffset.UtcNow);
        Assert.Equal(41, upgraded.RequiredPolicyGeneration);
    }

    [Fact]
    public void IncomingRequiredSignal_DoesNotCrossOwnedGenerationBoundary()
    {
        Assert.True(AgentUpdateLocalService.IsRequiredSignalCurrent(
            required: true,
            capturedGeneration: 42,
            lifecycleGeneration: 42));
        Assert.False(AgentUpdateLocalService.IsRequiredSignalCurrent(
            required: true,
            capturedGeneration: 41,
            lifecycleGeneration: 42));
        Assert.False(AgentUpdateLocalService.IsRequiredSignalCurrent(
            required: false,
            capturedGeneration: 42,
            lifecycleGeneration: 42));

        var historicalMarker = new AgentUpdateJournal
        {
            AttemptId = "historical-required-attempt",
            Phase = AgentUpdateStates.Blocked,
            Required = true,
            LifecycleGeneration = 41,
            RequiredPolicyGeneration = 41,
        };
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(
            historicalMarker,
            required: false,
            lifecycleGeneration: 42));
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

    // Unit/support fixture only: this creates the disposable attempt layout
    // without blessing it as a protected machine update root.
    private static string CreateDisposableAttemptLayout(string root, string attemptId)
    {
        var directory = Path.Combine(root, "attempts", AgentUpdateSecurity.AttemptDirectoryPrefix + attemptId);
        Directory.CreateDirectory(directory);
        return directory;
    }

    // Unit/support writer only: mirrors the attempt-ID compare and durable
    // journal roundtrip; it is not native protected locking/ACL acceptance.
    private static Func<string, Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> DisposableJournalWriter(string root)
        => (attemptId, transition) =>
        {
            var path = Path.Combine(root, "transaction.json");
            var store = new AgentUpdateJournalStore(root);
            var before = store.Read();
            if (!string.Equals(before.AttemptId, attemptId, StringComparison.Ordinal))
                throw new InvalidOperationException("Update attempt is no longer active.");
            var after = transition(before) with { Revision = checked(before.Revision + 1) };
            AgentUpdateDurableFile.Write(path, root, after);
            return new AgentUpdateJournalStore(root).Read();
        };

    // Unit/support writer only: mirrors the canonical journal Change roundtrip
    // for no-attempt recovery; it is not native protected locking/ACL acceptance.
    private static Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> DisposableJournalChange(string root)
        => transition =>
        {
            var path = Path.Combine(root, "transaction.json");
            var store = new AgentUpdateJournalStore(root);
            var before = store.Read();
            var after = transition(before) with { Revision = checked(before.Revision + 1) };
            AgentUpdateDurableFile.Write(path, root, after);
            return new AgentUpdateJournalStore(root).Read();
        };

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
