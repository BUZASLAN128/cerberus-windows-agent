using System.Text.Json;
using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using Xunit.Abstractions;

namespace Cerberus.Agent.Core.Tests;

// Real isolated DPAPI/filesystem persistence, controlled SCM/HTTP boundaries.
// Crash fixtures copy actual durable checkpoints, not imagined journal states.
// This is unit/support evidence, not installed SYSTEM/SCM acceptance.
public sealed class AgentEnrollmentTransactionTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData("scm")]
    [InlineData("probe")]
    [InlineData("stale-proof")]
    [InlineData("cancel")]
    public async Task StagedRegistrationFailurePreservesOriginalCiphertextAndGeneration(string failure)
    {
        using var fixture = await Fixture.CreateAsync();
        var prior = await File.ReadAllBytesAsync(fixture.ActivePath);
        var before = await fixture.Lifecycle.LoadAsync(default);
        var registration = await AgentServiceProvisioning.PrepareRegistrationForInstallAsync(
            fixture.User, fixture.Active, fixture.Pending, default,
            before with { State = AgentLifecycleState.NeedsReenrollment });
        // Metadata publication is a controlled boundary here; no host path is used.
        await fixture.WriteMarkerAsync();
        Assert.Equal(prior, await File.ReadAllBytesAsync(fixture.ActivePath));
        using var cancelled = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<Exception>(() => AgentServiceProvisioning.InstallPreparedRegistrationAsync(
            registration, fixture.User, clearUserAfterSuccess: true,
            () =>
            {
                if (failure == "scm") throw new IOException("Controlled SCM failure.");
                if (failure == "cancel") cancelled.Cancel();
                return Task.CompletedTask;
            },
            ct =>
            {
                ct.ThrowIfCancellationRequested();
                return Task.FromResult(new AgentLocalControlResponse(false, failure));
            }, cancelled.Token));
        Assert.Equal(prior, await File.ReadAllBytesAsync(fixture.ActivePath));
        Assert.Equal(before, await fixture.Lifecycle.LoadAsync(default));
        Assert.Equal("new-agent", (await fixture.User.LoadAsync(default)).Identity.AgentId);
        Assert.Equal("new-agent", (await fixture.Pending.LoadAsync(default)).Identity.AgentId);
    }

    [Fact]
    public async Task RetryPreservesPendingRefreshRotationAndHardRevocationStillDeniesStaging()
    {
        using var fixture = await Fixture.CreateAsync();
        var before = await fixture.Lifecycle.LoadAsync(default);
        await fixture.Pending.SaveAsync(new("new-agent", "tenant"), "rotated-pending", "new-key", "https://backend.invalid", null, null, default);
        var pendingBytes = await File.ReadAllBytesAsync(fixture.PendingPath);
        var activeBytes = await File.ReadAllBytesAsync(fixture.ActivePath);
        await AgentServiceProvisioning.PrepareRegistrationForInstallAsync(fixture.User, fixture.Active, fixture.Pending, default,
            before with { State = AgentLifecycleState.NeedsReenrollment });
        Assert.Equal(pendingBytes, await File.ReadAllBytesAsync(fixture.PendingPath));
        await Assert.ThrowsAsync<InvalidOperationException>(() => AgentServiceProvisioning.PrepareRegistrationForInstallAsync(
            fixture.User, fixture.Active, fixture.Pending, default,
            before with { State = AgentLifecycleState.Retired, ReasonCode = AgentLifecycleStatePolicy.AgentRevokedCode }));
        Assert.Equal(activeBytes, await File.ReadAllBytesAsync(fixture.ActivePath));
        Assert.Equal(before, await fixture.Lifecycle.LoadAsync(default));
    }

    [Fact]
    public async Task ValidatedPublicationCommitsOnceAndOrdinaryRefreshStillWorks()
    {
        using var fixture = await Fixture.CreateAsync();
        var before = await fixture.Lifecycle.LoadAsync(default);
        var pendingBytes = await File.ReadAllBytesAsync(fixture.PendingPath);
        var adopted = await fixture.Lifecycle.CommitEnrollmentAsync(before.Generation, fixture.Nonce,
            ct => fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync, ct), default);
        Assert.Equal(pendingBytes, await File.ReadAllBytesAsync(fixture.ActivePath));
        Assert.Equal(before.Generation + 1, adopted.Generation);
        Assert.Equal(fixture.Nonce, adopted.LastEnrollmentNonce);
        Assert.False(File.Exists(fixture.JournalPath));
        Assert.False(File.Exists(fixture.PendingPath));
        await Assert.ThrowsAsync<AgentLifecycleDormantException>(() => fixture.Lifecycle.CommitEnrollmentAsync(
            adopted.Generation, fixture.Nonce, _ => throw new InvalidOperationException("Must reject before publication."), default));
        Assert.Equal(adopted, await fixture.Lifecycle.LoadAsync(default));
        await fixture.Active.SaveAsync(new("new-agent", "tenant"), "normal-rotation", "new-key", "https://backend.invalid", null, null, default);
        Assert.Equal("normal-rotation", (await fixture.Active.LoadAsync(default)).RefreshToken);
        Assert.Equal(adopted, await fixture.Lifecycle.LoadAsync(default));
    }

    [Fact]
    public async Task CancellationAfterCredentialPublicationBeforeNonceCommitRollsBackExactBytes()
    {
        using var fixture = await Fixture.CreateAsync();
        var prior = await File.ReadAllBytesAsync(fixture.ActivePath);
        var before = await fixture.Lifecycle.LoadAsync(default);
        using var cancelled = new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Lifecycle.CommitEnrollmentAsync(before.Generation, fixture.Nonce,
            async ct =>
            {
                var lease = await fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync, ct);
                Assert.NotEqual(prior, await File.ReadAllBytesAsync(fixture.ActivePath));
                cancelled.Cancel();
                return lease;
            }, cancelled.Token));
        Assert.Equal(prior, await File.ReadAllBytesAsync(fixture.ActivePath));
        Assert.Equal(before, await fixture.Lifecycle.LoadAsync(default));
        Assert.False(File.Exists(fixture.JournalPath));
        Assert.True(File.Exists(fixture.PendingPath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RestartResolvesActualPublicationCheckpointFromCommittedNonce(bool committed)
    {
        using var fixture = await Fixture.CreateAsync();
        var prior = await File.ReadAllBytesAsync(fixture.ActivePath);
        var next = await File.ReadAllBytesAsync(fixture.PendingPath);
        var before = await fixture.Lifecycle.LoadAsync(default);
        Fixture? crash = null;
        try
        {
            if (committed)
            {
                await fixture.Lifecycle.CommitEnrollmentAsync(before.Generation, fixture.Nonce, async ct =>
                    new CheckpointLease(await fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync, ct),
                        () => crash = fixture.CopyCrashCheckpoint()), default);
            }
            else
            {
                await using var publication = await fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync, default);
                crash = fixture.CopyCrashCheckpoint();
            }
            Assert.NotNull(crash);
            await Assert.ThrowsAsync<InvalidOperationException>(() => crash.Transaction.AcquireResolvedAccessAsync(default));
            var decision = await crash.Lifecycle.LoadAsync(default);
            await crash.Transaction.RecoverWithLockAsync(decision, default);
            Assert.Equal(committed ? next : prior, await File.ReadAllBytesAsync(crash.ActivePath));
            Assert.Equal(decision, await crash.Lifecycle.LoadAsync(default));
            Assert.Equal(!committed, File.Exists(crash.PendingPath));
            Assert.False(File.Exists(crash.JournalPath));
            Assert.False(File.Exists(crash.BackupPath));
            using var access = await crash.Transaction.AcquireResolvedAccessAsync(default);
        }
        finally { crash?.Dispose(); }
    }

    [Fact]
    public async Task RestartAfterRollbackBeforeJournalDeletionIsIdempotent()
    {
        using var fixture = await Fixture.CreateAsync();
        var prior = await File.ReadAllBytesAsync(fixture.ActivePath);
        var before = await fixture.Lifecycle.LoadAsync(default);
        Fixture crash;
        await using (await fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync, default))
            crash = fixture.CopyCrashCheckpoint();
        using (crash)
        {
            await File.WriteAllBytesAsync(crash.ActivePath, prior);
            File.Delete(crash.BackupPath);
            await crash.Transaction.RecoverWithLockAsync(await crash.Lifecycle.LoadAsync(default), default);
            Assert.Equal(prior, await File.ReadAllBytesAsync(crash.ActivePath));
            Assert.False(File.Exists(crash.JournalPath));
        }
    }

    [Fact]
    public async Task InterruptedFirstEnrollmentRestoresAbsenceRatherThanLeavingUncommittedIdentity()
    {
        using var fixture = await Fixture.CreateAsync();
        File.Delete(fixture.ActivePath);
        var before = await fixture.Lifecycle.LoadAsync(default);
        await using (await fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync, default))
            Assert.True(File.Exists(fixture.ActivePath));
        Assert.False(File.Exists(fixture.ActivePath));
        Assert.True(File.Exists(fixture.PendingPath));
        Assert.Equal(before, await fixture.Lifecycle.LoadAsync(default));
    }

    [Fact]
    public async Task CommittedRecoveryRejectsConflictingMarkerInsteadOfDeletingAnotherProof()
    {
        using var fixture = await Fixture.CreateAsync();
        var before = await fixture.Lifecycle.LoadAsync(default);
        Fixture? crash = null;
        try
        {
            await fixture.Lifecycle.CommitEnrollmentAsync(before.Generation, fixture.Nonce, async ct =>
                new CheckpointLease(await fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync, ct),
                    () => crash = fixture.CopyCrashCheckpoint()), default);
            Assert.NotNull(crash);
            await crash.WriteMarkerAsync(); // a different nonce, not the consumed proof
            var active = await File.ReadAllBytesAsync(crash.ActivePath);
            var decision = await crash.Lifecycle.LoadAsync(default);
            await Assert.ThrowsAsync<InvalidDataException>(() => crash.Transaction.RecoverWithLockAsync(decision, default));
            Assert.Equal(active, await File.ReadAllBytesAsync(crash.ActivePath));
            Assert.True(File.Exists(crash.PendingPath));
            await Assert.ThrowsAsync<InvalidOperationException>(() => crash.Transaction.AcquireResolvedAccessAsync(default));
        }
        finally { crash?.Dispose(); }
    }

    [Theory]
    [InlineData("journal")]
    [InlineData("backup")]
    [InlineData("active")]
    [InlineData("stale-generation")]
    public async Task CorruptOrStaleRecoveryBindingFailsClosedWithoutFurtherPublication(string corruption)
    {
        using var fixture = await Fixture.CreateAsync();
        var before = await fixture.Lifecycle.LoadAsync(default);
        Fixture crash;
        await using (await fixture.Transaction.BeginLockedAsync(before.Generation, fixture.Nonce, fixture.Lifecycle.LoadAsync, default))
            crash = fixture.CopyCrashCheckpoint();
        using (crash)
        {
            if (corruption != "stale-generation")
                await File.WriteAllTextAsync(corruption switch { "journal" => crash.JournalPath, "backup" => crash.BackupPath, _ => crash.ActivePath }, "corrupt");
            var active = await File.ReadAllBytesAsync(crash.ActivePath);
            var decision = await crash.Lifecycle.LoadAsync(default);
            if (corruption == "stale-generation") decision = decision with { Generation = decision.Generation + 1 };
            await Assert.ThrowsAnyAsync<Exception>(() => crash.Transaction.RecoverWithLockAsync(decision, default));
            Assert.Equal(active, await File.ReadAllBytesAsync(crash.ActivePath));
            await Assert.ThrowsAsync<InvalidOperationException>(() => crash.Transaction.AcquireResolvedAccessAsync(default));
        }
    }

    [Fact]
    public void ManualHeartbeatUsesCanonicalServiceWireShape()
    {
        var json = JsonSerializer.Serialize(AgentLocalControlService.CreateManualHeartbeat());
        using var document = JsonDocument.Parse(json);
        var body = document.RootElement;
        Assert.Equal("service", body.GetProperty("runtime_mode").GetString());
        Assert.Equal("connected", body.GetProperty("status").GetString());
        Assert.InRange(body.GetProperty("agent_version").GetString()!.Length, 1, 50);
        Assert.Equal(JsonValueKind.Array, body.GetProperty("supported_schema_versions").ValueKind);
        Assert.Equal(JsonValueKind.Array, body.GetProperty("capabilities").ValueKind);
        output.WriteLine("MANUAL_HEARTBEAT_JSON=" + json);
    }

    private sealed class CheckpointLease(IAsyncDisposable inner, Action checkpoint) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            try { checkpoint(); }
            finally { await inner.DisposeAsync(); }
        }
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; }
        internal string Nonce { get; } = Guid.NewGuid().ToString("N");
        internal string DirectoryPath => Path.Combine(Root, "Provisioning");
        internal string ActivePath => Path.Combine(Root, "Active", "secrets.json");
        internal string PendingPath => Path.Combine(DirectoryPath, "Pending", "secrets.json");
        internal string JournalPath => Path.Combine(DirectoryPath, "credential-publication.json");
        internal string BackupPath => Path.Combine(DirectoryPath, "prior-active.dpapi");
        internal DpapiSecretStore Active { get; }
        internal DpapiSecretStore User { get; }
        internal DpapiSecretStore Pending { get; }
        internal DurableAgentLifecycleStateStore Lifecycle { get; }
        internal AgentCredentialPublication Transaction { get; }
        private Fixture(string root)
        {
            Root = root;
            Active = new(SecretStoreScope.User, Path.GetDirectoryName(ActivePath));
            User = new(SecretStoreScope.User, Path.Combine(root, "User"));
            Pending = new(SecretStoreScope.User, Path.GetDirectoryName(PendingPath));
            Lifecycle = new(Path.Combine(root, "Lifecycle", "lifecycle.json"));
            Transaction = new(DirectoryPath, ActivePath);
        }

        internal static async Task<Fixture> CreateAsync()
        {
            var fixture = new Fixture(NewRoot());
            await fixture.Active.SaveAsync(new("old-agent", "tenant"), "old-refresh", "old-key", "https://backend.invalid", null, null, default);
            await fixture.User.SaveAsync(new("new-agent", "tenant"), "new-refresh", "new-key", "https://backend.invalid", null, null, default);
            await fixture.Pending.SaveAsync(new("new-agent", "tenant"), "new-refresh", "new-key", "https://backend.invalid", null, null, default);
            var initial = await fixture.Lifecycle.LoadAsync(default);
            await fixture.Lifecycle.TrySaveAsync(initial, initial.Revision, default);
            await fixture.WriteMarkerAsync();
            return fixture;
        }

        internal Task WriteMarkerAsync() => File.WriteAllTextAsync(Path.Combine(DirectoryPath, "enrollment-adoption.json"),
            JsonSerializer.Serialize(new { nonce = Nonce }));

        internal Fixture CopyCrashCheckpoint()
        {
            var root = NewRoot();
            foreach (var path in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
            {
                if (path.EndsWith(".lock", StringComparison.Ordinal)) continue;
                var destination = Path.Combine(root, Path.GetRelativePath(Root, path));
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(path, destination);
            }
            return new Fixture(root);
        }

        private static string NewRoot() => Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        public void Dispose() { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
    }
}
