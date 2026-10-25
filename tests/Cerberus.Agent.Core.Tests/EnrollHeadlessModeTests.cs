using Cerberus.Agent.App;
using System.Security.AccessControl;
using System.Security.Principal;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class EnrollHeadlessModeTests
{
    private static readonly string Proof = HeadlessEnrollmentTests.Proof();

    [Fact]
    public async Task Running_service_gets_the_credentials_through_adopt_and_the_fingerprint_is_printed()
    {
        var host = new FakeHost { State = HeadlessServiceState.Running };

        var (exit, stdout, stderr) = await Execute(host, installService: false);

        Assert.Equal(0, exit);
        Assert.Equal(1, host.Http.Requests.Count);
        Assert.Equal([false], host.ActivateCalls);
        Assert.False(host.UserScope);
        var line = stdout.Trim();
        Assert.Matches("^Agent key fingerprint=sha256:[0-9a-f]{64}$", line);
        Assert.Equal(AgentKeyFingerprint.FromPrivateKeyPem(host.Store.Saved!.Value.PrivateKeyPem), line["Agent key fingerprint=".Length..]);
        Assert.StartsWith(line, host.FingerprintFile);
        Assert.Contains("agent_id=agent-0001", host.FingerprintFile);
        Assert.Equal("", stderr);
    }

    [Fact]
    public async Task Stopped_service_is_started_for_the_cli_and_for_the_installer_it_is_left_stopped_and_committed_directly()
    {
        var cli = new FakeHost { State = HeadlessServiceState.Stopped, StateAfterEnsure = HeadlessServiceState.Running };
        Assert.Equal(0, (await Execute(cli, installService: false)).Exit);
        Assert.Equal([true], cli.EnsureCalls);
        Assert.Equal([false], cli.ActivateCalls);

        var installer = new FakeHost { State = HeadlessServiceState.Stopped, StateAfterEnsure = HeadlessServiceState.Stopped };
        Assert.Equal(0, (await Execute(installer, installService: true, fromInstaller: true)).Exit);
        Assert.Equal([false], installer.EnsureCalls);
        Assert.Equal([true], installer.ActivateCalls);
    }

    [Fact]
    public async Task Service_that_never_runs_after_a_spent_proof_exits_four()
    {
        var host = new FakeHost { State = HeadlessServiceState.Stopped, StateAfterEnsure = HeadlessServiceState.Stopped };

        var (exit, _, stderr) = await Execute(host, installService: false);

        Assert.Equal(4, exit);
        Assert.Contains("service_not_running", stderr);
        Assert.Empty(host.ActivateCalls);
        Assert.Null(host.FingerprintFile);
    }

    [Fact]
    public async Task Adopt_failure_exits_four_with_the_service_code_and_prints_no_fingerprint()
    {
        var host = new FakeHost { State = HeadlessServiceState.Running, ActivateResult = "state_refused" };

        var (exit, stdout, stderr) = await Execute(host, installService: false);

        Assert.Equal(4, exit);
        Assert.Contains("state_refused", stderr);
        Assert.Equal("", stdout);
        Assert.Null(host.FingerprintFile);
    }

    [Fact]
    public async Task Rejected_request_does_not_activate_or_write_anything()
    {
        var host = new FakeHost { State = HeadlessServiceState.Running };
        host.Http = new HeadlessEnrollmentTests.FakeHandler().Reply(401, "");

        var (exit, stdout, stderr) = await Execute(host, installService: false);

        Assert.Equal(4, exit);
        Assert.Empty(host.ActivateCalls);
        Assert.Equal(0, host.Store.SaveCount);
        Assert.Equal("", stdout);
        Assert.Contains("Request a new proof", stderr);
    }

    [Fact]
    public async Task Local_preconditions_fail_with_exit_two_before_any_request()
    {
        var notAdmin = new FakeHost { Admin = false };
        var installerNotSystem = new FakeHost { LocalSystem = false };
        var noBackend = new FakeHost { Backend = null };
        var blockedBackend = new FakeHost { BackendThrows = true };

        Assert.Equal(2, (await Execute(notAdmin, false)).Exit);
        Assert.Equal(2, (await Execute(installerNotSystem, true, fromInstaller: true)).Exit);
        Assert.Equal(2, (await Execute(noBackend, false)).Exit);
        Assert.Equal(2, (await Execute(blockedBackend, false)).Exit);
        Assert.Equal(2, (await Execute(new FakeHost(), false, proof: "bad")).Exit);
        foreach (var host in new[] { notAdmin, installerNotSystem, noBackend, blockedBackend })
            Assert.Empty(host.Http.Requests);
    }

    [Fact]
    public async Task Unreadable_local_state_exits_seven_without_a_request()
    {
        var host = new FakeHost { LifecycleThrows = true };

        var (exit, _, _) = await Execute(host, false);

        Assert.Equal(7, exit);
        Assert.Empty(host.Http.Requests);
    }

    [Fact]
    public async Task Replacing_a_key_logs_the_old_fingerprint_and_the_proof_is_never_logged()
    {
        var host = new FakeHost
        {
            State = HeadlessServiceState.Running,
            Lifecycle = new AgentLifecycleSnapshot(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required"),
            HasCredentials = true,
            OldFingerprintLine = "Agent key fingerprint=sha256:" + new string('a', 64),
        };

        var (exit, stdout, stderr) = await Execute(host, false);

        Assert.Equal(0, exit);
        Assert.Contains("replaced old=sha256:" + new string('a', 64), host.Log.Text);
        Assert.DoesNotContain(Proof, host.Log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain(Proof, stdout + stderr, StringComparison.Ordinal);
        Assert.DoesNotContain(Proof, host.FingerprintFile ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public void Fingerprint_file_that_a_standard_user_could_write_reads_as_no_fingerprint()
    {
        var path = Path.Combine(Path.GetTempPath(), "cerberus-fp-" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            File.WriteAllText(path, "Agent key fingerprint=sha256:" + new string('c', 64) + Environment.NewLine);
            var acl = new FileInfo(path).GetAccessControl();
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.WriteData, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(acl);

            Assert.Null(ProtectedFingerprintFile.ReadFirstLine(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Protected_fingerprint_file_round_trips_with_a_protected_dacl_that_gives_users_read_only()
    {
        using var identity = WindowsIdentity.GetCurrent();
        // Setting the SYSTEM/Administrators owner needs an elevated token; the unelevated case is not covered here.
        if (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return;
        var path = Path.Combine(Path.GetTempPath(), "cerberus-fp-" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            var line = "Agent key fingerprint=sha256:" + new string('d', 64);
            ProtectedFingerprintFile.Write(path, line + Environment.NewLine + "agent_id=a1" + Environment.NewLine);

            Assert.Equal(line, ProtectedFingerprintFile.ReadFirstLine(path));
            var acl = new FileInfo(path).GetAccessControl();
            Assert.True(acl.AreAccessRulesProtected);
            var users = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
                .Where(r => ((SecurityIdentifier)r.IdentityReference).IsWellKnown(WellKnownSidType.BuiltinUsersSid)).ToList();
            Assert.Single(users);
            Assert.Equal(FileSystemRights.Read, users[0].FileSystemRights & ~FileSystemRights.Synchronize);
        }
        finally { File.Delete(path); }
    }

#if CERBERUS_SERVER_PROFILE
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Server_profile_without_an_installed_service_exits_two_before_the_proof_is_spent(bool installService)
    {
        var host = new FakeHost { State = HeadlessServiceState.NotInstalled };

        var (exit, _, stderr) = await Execute(host, installService);

        Assert.Equal(2, exit);
        Assert.Contains("service_not_installed", stderr);
        Assert.Empty(host.Http.Requests);
        Assert.Equal(0, host.Store.SaveCount);
    }

    [Fact]
    public void Server_profile_has_no_service_install_seam()
    {
        Assert.Null(typeof(IHeadlessHost).GetMethod("InstallDesktopService"));
    }
#else
    [Fact]
    public async Task Desktop_without_a_service_saves_to_the_user_store_and_installs_only_when_asked()
    {
        var plain = new FakeHost { State = HeadlessServiceState.NotInstalled };
        Assert.Equal(0, (await Execute(plain, installService: false)).Exit);
        Assert.True(plain.UserScope);
        Assert.Equal(0, plain.InstallCalls);
        Assert.Empty(plain.ActivateCalls);

        var install = new FakeHost { State = HeadlessServiceState.NotInstalled };
        Assert.Equal(0, (await Execute(install, installService: true)).Exit);
        Assert.Equal(1, install.InstallCalls);
    }
#endif

    [Fact]
    public async Task Cancellation_during_activation_after_a_2xx_exits_four_as_a_spent_proof()
    {
        using var cts = new CancellationTokenSource();
        var host = new FakeHost { CancelOnActivate = cts };

        var result = await Execute(host, installService: false, ct: cts.Token);

        Assert.Equal(4, result.Exit);
        Assert.Contains("activation_failed", result.Stderr, StringComparison.Ordinal);
        Assert.Contains("were not activated (OperationCanceledException)", host.Log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain(Proof, host.Log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain(Proof, result.Stderr, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cancellation_before_the_request_completes_exits_five()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var host = new FakeHost();

        var result = await Execute(host, installService: false, ct: cts.Token);

        Assert.Equal(5, result.Exit);
        Assert.Empty(host.Http.Requests);
        Assert.Empty(host.ActivateCalls);
    }

    private static async Task<(int Exit, string Stdout, string Stderr)> Execute(
        FakeHost host, bool installService, bool fromInstaller = false, string? proof = null, CancellationToken ct = default)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var exit = await EnrollHeadlessMode.ExecuteAsync(proof ?? Proof, fromInstaller, installService, host, stdout, stderr, ct);
        return (exit, stdout.ToString(), stderr.ToString());
    }

    private sealed class FakeHost : IHeadlessHost
    {
        public HeadlessServiceState State { get; init; } = HeadlessServiceState.Running;
        public HeadlessServiceState StateAfterEnsure { get; init; } = HeadlessServiceState.Running;
        public bool Admin { get; init; } = true;
        public bool LocalSystem { get; init; } = true;
        public string? Backend { get; init; } = "https://backend.example";
        public bool BackendThrows { get; init; }
        public bool LifecycleThrows { get; init; }
        public bool HasCredentials { get; init; }
        public AgentLifecycleSnapshot Lifecycle { get; init; } = new();
        public string? OldFingerprintLine { get; init; }
        public string? ActivateResult { get; init; }
        public CancellationTokenSource? CancelOnActivate { get; init; }

        public HeadlessEnrollmentTests.FakeHandler Http { get; set; } = new HeadlessEnrollmentTests.FakeHandler()
            .Reply(200, "{\"agent_id\":\"agent-0001\",\"tenant_id\":\"tenant-1\",\"agent_refresh_token\":\"rt-secret\"}");
        public HeadlessEnrollmentTests.MemoryStore Store { get; } = new();
        public HeadlessEnrollmentTests.CaptureLog Log { get; } = new();
        public List<bool> EnsureCalls { get; } = [];
        public List<bool> ActivateCalls { get; } = [];
        public bool UserScope { get; private set; }
        public int InstallCalls { get; private set; }
        public string? FingerprintFile { get; private set; }

        public bool IsAdministrator => Admin;
        public bool IsLocalSystem => LocalSystem;
        public HeadlessServiceState GetServiceState() => State;

        public Task<HeadlessServiceState> EnsureRunningAsync(bool startIfStopped, CancellationToken ct)
        {
            EnsureCalls.Add(startIfStopped);
            return Task.FromResult(State == HeadlessServiceState.Stopped ? StateAfterEnsure : State);
        }

        public string? ResolveBackendUrl() => BackendThrows ? throw new InvalidOperationException("blocked") : Backend;
        public HeadlessEnrollmentOptions BuildOptions(string backendUrl) => HeadlessEnrollmentTests.Options();
        public bool HasMachineCredentials() => HasCredentials;

        public Task<AgentLifecycleSnapshot> LoadLifecycleAsync(CancellationToken ct)
            => LifecycleThrows ? throw new IOException("locked") : Task.FromResult(Lifecycle);

        public ISecretStore OpenDestination(bool userScope)
        {
            UserScope = userScope;
            return Store;
        }

        public HttpClient CreateHttpClient(Uri backend) => new(Http) { BaseAddress = backend };

        public Task<string?> ActivateAsync(bool commitDirectly, CancellationToken ct)
        {
            ActivateCalls.Add(commitDirectly);
            if (CancelOnActivate is { } cts)
            {
                cts.Cancel();
                ct.ThrowIfCancellationRequested();
            }
            return Task.FromResult(ActivateResult);
        }

        public string? ReadFingerprintLine() => OldFingerprintLine;
        public void WriteFingerprintFile(string content) => FingerprintFile = content;
        public Task WriteTenantContextAsync(AgentIdentity identity, string? tenantName, CancellationToken ct) => Task.CompletedTask;
        public IAgentLogger OpenLog() => Log;

#if !CERBERUS_SERVER_PROFILE
        public void InstallDesktopService() => InstallCalls++;
#endif
    }
}
