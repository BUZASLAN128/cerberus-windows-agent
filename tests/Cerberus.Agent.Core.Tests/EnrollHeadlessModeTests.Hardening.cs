using Cerberus.Agent.App;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Cancelled-but-committed adopt, service-state rechecks, data-root gate and stale-pending cleanup of the enroll run.
public sealed partial class EnrollHeadlessModeTests
{
    private static readonly AgentLifecycleSnapshot Gen0 = new();

    [Fact]
    public async Task Cancelled_activation_after_the_service_committed_the_adoption_reports_success()
    {
        using var cts = new CancellationTokenSource();
        var inner = new FakeHost
        {
            CancelOnActivate = cts,
            DiscardThrows = true,
            LifecycleSequence = [Gen0, new AgentLifecycleSnapshot { Generation = 1 }],
        };
        var host = new SeamHost(inner) { CredentialStates = [false, true] };

        var (exit, stdout, stderr) = await ExecuteSeam(host, ct: cts.Token);

        Assert.Equal(0, exit);
        Assert.Matches("^Agent key fingerprint=sha256:[0-9a-f]{64}$", stdout.Trim());
        Assert.Equal("", stderr);
        Assert.Equal(0, inner.DiscardCalls);
        Assert.NotNull(inner.FingerprintFile);
    }

    [Theory]
    [InlineData("generation_unchanged")]
    [InlineData("no_machine_credentials")]
    [InlineData("cleanup_pending")]
    [InlineData("not_active")]
    public async Task Cancelled_activation_without_a_visible_commit_still_exits_four(string scenario)
    {
        using var cts = new CancellationTokenSource();
        var after = scenario switch
        {
            "generation_unchanged" => Gen0,
            "cleanup_pending" => new AgentLifecycleSnapshot { Generation = 1, QuiescenceComplete = false },
            "not_active" => new AgentLifecycleSnapshot(AgentLifecycleState.NeedsReenrollment) { Generation = 1 },
            _ => new AgentLifecycleSnapshot { Generation = 1 },
        };
        var inner = new FakeHost { CancelOnActivate = cts, LifecycleSequence = [Gen0, after] };
        var host = new SeamHost(inner) { CredentialStates = [false, scenario != "no_machine_credentials"] };

        var (exit, stdout, stderr) = await ExecuteSeam(host, ct: cts.Token);

        Assert.Equal(4, exit);
        Assert.Contains("activation_failed", stderr, StringComparison.Ordinal);
        Assert.Equal("", stdout);
        Assert.Null(inner.FingerprintFile);
    }

    [Fact]
    public async Task Stopped_service_with_pending_cleanup_fails_at_once_without_sending_the_proof()
    {
        var inner = new FakeHost
        {
            State = HeadlessServiceState.Stopped,
            Lifecycle = new AgentLifecycleSnapshot { QuiescenceComplete = false },
        };

        var (exit, stdout, stderr) = await ExecuteSeam(new SeamHost(inner), fromInstaller: true);

        Assert.Equal(HeadlessEnrollmentExit.Unavailable, exit);
        Assert.Contains("service_not_ready", stderr, StringComparison.Ordinal);
        Assert.Equal("", stdout);
        Assert.Equal(0, inner.DelayCalls);
        Assert.Empty(inner.Http.Requests);
        Assert.Equal(0, inner.Store.SaveCount);
    }

    [Theory]
    [InlineData("Stopped")]
    [InlineData("Other")]
    [InlineData("NotInstalled")]
    public async Task Service_that_is_no_longer_running_right_before_the_send_exits_five_without_the_proof(string laterName)
    {
        var later = Enum.Parse<HeadlessServiceState>(laterName);
        var inner = new FakeHost { State = HeadlessServiceState.Running };
        var host = new SeamHost(inner) { ServiceStates = [HeadlessServiceState.Running, later] };

        var (exit, _, stderr) = await ExecuteSeam(host);

        Assert.Equal(HeadlessEnrollmentExit.Unavailable, exit);
        Assert.Contains("service_not_ready", stderr, StringComparison.Ordinal);
        Assert.Empty(inner.Http.Requests);
        Assert.Equal(0, inner.Store.SaveCount);
        Assert.Empty(inner.ActivateCalls);
    }

    [Fact]
    public async Task Untrusted_data_root_refuses_with_exit_seven_before_anything_is_written_or_sent()
    {
        var inner = new FakeHost();
        var host = new SeamHost(inner) { DataRootTrusted = false };

        var (exit, stdout, stderr) = await ExecuteSeam(host);

        Assert.Equal(HeadlessEnrollmentExit.Refused, exit);
        Assert.Contains("data_root_untrusted", stderr, StringComparison.Ordinal);
        Assert.Equal("", stdout);
        Assert.Equal(1, host.DataRootCalls);
        Assert.Empty(inner.Http.Requests);
        Assert.Equal(0, inner.Store.SaveCount);
        Assert.DoesNotContain("stale", string.Join(",", host.Events));
        Assert.Null(inner.FingerprintFile);
    }

    [Fact]
    public async Task Stale_staged_credentials_are_removed_before_the_proof_is_sent()
    {
        var inner = new FakeHost();
        var host = new SeamHost(inner) { StaleRemoved = true };

        var (exit, _, _) = await ExecuteSeam(host);

        Assert.Equal(0, exit);
        Assert.Equal(["data_root", "log", "stale", "http"], host.Events);
        Assert.Contains("Stale pending enrollment credentials were removed", inner.Log.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Failing_stale_cleanup_does_not_stop_the_enrollment()
    {
        var inner = new FakeHost();
        var host = new SeamHost(inner) { StaleThrows = true };

        var (exit, _, _) = await ExecuteSeam(host);

        Assert.Equal(0, exit);
        Assert.Equal(1, inner.Http.Requests.Count);
        Assert.Contains("Stale pending enrollment could not be removed (IOException)", inner.Log.Text, StringComparison.Ordinal);
    }

    private static async Task<(int Exit, string Stdout, string Stderr)> ExecuteSeam(
        IHeadlessHost host, bool installService = false, bool fromInstaller = false, CancellationToken ct = default)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exit = await EnrollHeadlessMode.ExecuteAsync(Proof, fromInstaller, installService, host, stdout, stderr, ct);
        return (exit, stdout.ToString(), stderr.ToString());
    }

    /// <summary>Wraps <see cref="FakeHost"/> with per-read service/credential states and the data-root and stale-cleanup seams.</summary>
    private sealed class SeamHost(FakeHost inner) : IHeadlessHost
    {
        private int _stateReads;
        private int _credentialReads;

        public IReadOnlyList<HeadlessServiceState>? ServiceStates { get; init; }
        public IReadOnlyList<bool>? CredentialStates { get; init; }
        public bool DataRootTrusted { get; init; } = true;
        public bool StaleRemoved { get; init; }
        public bool StaleThrows { get; init; }
        public int DataRootCalls { get; private set; }
        public List<string> Events { get; } = [];
        /// <summary>Set to take part in the enroll lock; null keeps the interface default (no lock).</summary>
        public Func<TimeSpan, IDisposable?>? LockFactory { get; init; }
        public List<TimeSpan> LockWaits { get; } = [];

        public IDisposable? TryAcquireEnrollLock(TimeSpan wait)
        {
            if (LockFactory is null)
                return NoLock.Instance;
            LockWaits.Add(wait);
            var held = LockFactory(wait);
            if (held is null)
                return null;
            Events.Add("lock");
            return new Lease(held, () => Events.Add("unlock"));
        }

        private sealed class Lease(IDisposable inner, Action released) : IDisposable
        {
            public void Dispose()
            {
                inner.Dispose();
                released();
            }
        }

        public bool IsAdministrator => inner.IsAdministrator;
        public bool IsLocalSystem => inner.IsLocalSystem;

        public HeadlessServiceState GetServiceState()
            => ServiceStates is { Count: > 0 } s ? s[Math.Min(_stateReads++, s.Count - 1)] : inner.GetServiceState();

        public Task<HeadlessServiceState> EnsureRunningAsync(bool startIfStopped, CancellationToken ct) => inner.EnsureRunningAsync(startIfStopped, ct);
        public string? ResolveBackendUrl() => inner.ResolveBackendUrl();
        public HeadlessEnrollmentOptions BuildOptions(string backendUrl) => inner.BuildOptions(backendUrl);

        public bool HasMachineCredentials()
            => CredentialStates is { Count: > 0 } c ? c[Math.Min(_credentialReads++, c.Count - 1)] : inner.HasMachineCredentials();

        public Task<AgentLifecycleSnapshot> LoadLifecycleAsync(CancellationToken ct) => inner.LoadLifecycleAsync(ct);
        public Task DelayAsync(TimeSpan delay, CancellationToken ct) => inner.DelayAsync(delay, ct);
        public ISecretStore OpenDestination(bool userScope) => inner.OpenDestination(userScope);

        public HttpClient CreateHttpClient(Uri backend)
        {
            Events.Add("http");
            return inner.CreateHttpClient(backend);
        }

        public Task<string?> ActivateAsync(bool commitDirectly, CancellationToken ct) => inner.ActivateAsync(commitDirectly, ct);
        public string? ReadFingerprintLine() => inner.ReadFingerprintLine();
        public void WriteFingerprintFile(string content) => inner.WriteFingerprintFile(content);
        public Task WriteTenantContextAsync(AgentIdentity identity, string? tenantName, CancellationToken ct)
            => inner.WriteTenantContextAsync(identity, tenantName, ct);
        public IAgentLogger OpenLog()
        {
            Events.Add("log");
            return inner.OpenLog();
        }
        public Task DiscardPendingEnrollmentAsync(CancellationToken ct) => inner.DiscardPendingEnrollmentAsync(ct);

        public bool EnsureDataRootProtected()
        {
            DataRootCalls++;
            Events.Add("data_root");
            return DataRootTrusted;
        }

        public Task<bool> DiscardStalePendingEnrollmentAsync(CancellationToken ct)
        {
            Events.Add("stale");
            return StaleThrows ? throw new IOException("locked") : Task.FromResult(StaleRemoved);
        }

#if !CERBERUS_SERVER_PROFILE
        public void InstallDesktopService() => inner.InstallDesktopService();
#endif
    }
}
