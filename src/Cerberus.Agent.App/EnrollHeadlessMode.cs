using System.IO;
using System.Net.Http;
using System.Text;
using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App;

internal enum HeadlessServiceState { NotInstalled, Stopped, Starting, Running, Other }

/// <summary>Machine, service and file-system seam of <see cref="EnrollHeadlessMode"/>.</summary>
internal interface IHeadlessHost
{
    bool IsAdministrator { get; }
    bool IsLocalSystem { get; }
    HeadlessServiceState GetServiceState();
    /// <summary>Waits for a starting service; starts a stopped one only when asked. Returns the resulting state.</summary>
    Task<HeadlessServiceState> EnsureRunningAsync(bool startIfStopped, CancellationToken ct);
    /// <summary>The configured backend, or null. Throws InvalidOperationException when routing or scheme is not allowed.</summary>
    string? ResolveBackendUrl();
    HeadlessEnrollmentOptions BuildOptions(string backendUrl);
    bool HasMachineCredentials();
    Task<AgentLifecycleSnapshot> LoadLifecycleAsync(CancellationToken ct);
    /// <summary>Delay between state re-reads; tests replace it.</summary>
    Task DelayAsync(TimeSpan delay, CancellationToken ct) => Task.Delay(delay, ct);
    ISecretStore OpenDestination(bool userScope);
    HttpClient CreateHttpClient(Uri backend);
    /// <summary>Hands the saved pending credentials to the service (<c>false</c>) or commits them directly (<c>true</c>). Null on success, otherwise a code.</summary>
    Task<string?> ActivateAsync(bool commitDirectly, CancellationToken ct);
    string? ReadFingerprintLine();
    void WriteFingerprintFile(string content);
    Task WriteTenantContextAsync(AgentIdentity identity, string? tenantName, CancellationToken ct);
    IAgentLogger OpenLog();
    /// <summary>Server profile: creates or hardens the data folder before anything is written. False when it is not trustworthy. The desktop has no such gate.</summary>
    bool EnsureDataRootProtected() => true;
    /// <summary>Removes the staged pending credentials and the adopt marker. Server profile only; the desktop keeps them.</summary>
    Task DiscardPendingEnrollmentAsync(CancellationToken ct) => Task.CompletedTask;
    /// <summary>Server profile: removes staged pending credentials that no committed enrollment uses (left by a killed run). True when something was removed.</summary>
    Task<bool> DiscardStalePendingEnrollmentAsync(CancellationToken ct) => Task.FromResult(false);
    /// <summary>Server profile: the cross-process enroll lock. Null when another run holds it after <paramref name="wait"/>. Throws UnauthorizedAccessException when the lock cannot be trusted. The desktop has no such lock.</summary>
    IDisposable? TryAcquireEnrollLock(TimeSpan wait) => NoLock.Instance;
#if !CERBERUS_SERVER_PROFILE
    void InstallDesktopService();
#endif
}

internal sealed class NoLock : IDisposable
{
    internal static readonly NoLock Instance = new();
    public void Dispose() { }
}

/// <summary>
/// <c>--enroll-headless</c> and <c>--show-fingerprint</c>. Every local precondition runs before the
/// request, because a 2xx spends the proof. The proof is read once, never logged and never stored.
/// </summary>
internal static class EnrollHeadlessMode
{
    internal const string FingerprintFileName = "enrollment-fingerprint.txt";

    public static async Task<int> RunAsync(AgentArgs args, string[] rawArgs, CancellationToken ct)
    {
        var host = new WindowsHeadlessHost();
        var sources = (args.ProofFile is not null ? 1 : 0) + (args.ProofStdin ? 1 : 0) + (args.ProofFromInstaller ? 1 : 0);
        if (sources != 1)
        {
            Console.Error.WriteLine("Enrollment not completed: give exactly one of --proof-file, --proof-stdin, --proof-from-installer (exit 2).");
            return HeadlessEnrollmentExit.BadInput;
        }

        var raw = args.ProofFromInstaller ? ReadInstallerValue(rawArgs)
            : args.ProofFile is not null ? ReadFile(args.ProofFile)
            : await ReadStdinAsync(ct).ConfigureAwait(false);
        if (raw is null)
        {
            Console.Error.WriteLine("Enrollment not completed: the proof could not be read (exit 2).");
            return HeadlessEnrollmentExit.BadInput;
        }

        return await ExecuteAsync(raw, args.ProofFromInstaller, args.InstallService, host, Console.Out, Console.Error, ct)
            .ConfigureAwait(false);
    }

    public static int ShowFingerprint()
    {
        var line = new WindowsHeadlessHost().ReadFingerprintLine();
        if (line is null)
        {
            Console.Error.WriteLine("No enrolled key fingerprint found.");
            return HeadlessEnrollmentExit.BadInput;
        }
        Console.Out.WriteLine(line);
        return 0;
    }

    internal static async Task<int> ExecuteAsync(
        string rawProof,
        bool fromInstaller,
        bool installService,
        IHeadlessHost host,
        TextWriter stdout,
        TextWriter stderr,
        CancellationToken ct)
    {
        // The file logger writes under the data folder, so it opens only after the gate and the lock.
        var refused = Preflight(rawProof, fromInstaller, host, out var runLock);
        if (refused is { } early)
        {
            stderr.WriteLine($"Enrollment not completed: {early.Code} (exit {early.ExitCode}).{Hint(early.ExitCode)}");
            return early.ExitCode;
        }
        using var lease = runLock;
        var log = host.OpenLog();
        try
        {
            var code = await RunCoreAsync(rawProof, fromInstaller, installService, host, stdout, log, ct).ConfigureAwait(false);
            if (code.ExitCode != 0)
            {
                log.Warn($"Headless enrollment ended exit={code.ExitCode} code={code.Code}");
                stderr.WriteLine($"Enrollment not completed: {code.Code} (exit {code.ExitCode}).{Hint(code.ExitCode)}");
            }
            return code.ExitCode;
        }
        catch (OperationCanceledException)
        {
            log.Warn("Headless enrollment cancelled or timed out.");
            stderr.WriteLine($"Enrollment not completed: timed out (exit {HeadlessEnrollmentExit.Unavailable}).");
            return HeadlessEnrollmentExit.Unavailable;
        }
        finally
        {
            (log as IDisposable)?.Dispose();
        }
    }

    // Nothing here writes under the data folder: the gate runs first, then the lock (a file inside the gated folder).
    // A null result hands the lock to the caller, who holds it to the end of the run, adopt included.
    private static HeadlessEnrollmentResult? Preflight(string rawProof, bool fromInstaller, IHeadlessHost host, out IDisposable? lease)
    {
        lease = null;
        if (fromInstaller && !host.IsLocalSystem)
            return new(HeadlessEnrollmentExit.BadInput, "proof_from_installer_requires_local_system");
        if (!host.IsAdministrator)
            return new(HeadlessEnrollmentExit.BadInput, "administrator_required");
        if (!HeadlessEnrollmentProof.TryNormalize(rawProof, out _))
            return new(HeadlessEnrollmentExit.BadInput, "proof_invalid");
        // A standard user must not have pre-created the data folder or entries in it.
        if (!host.EnsureDataRootProtected())
            return new(HeadlessEnrollmentExit.Refused, "data_root_untrusted");
        // Before anything is staged or discarded: another run (or a rollback) may own the staged credentials.
        try { lease = host.TryAcquireEnrollLock(TimeSpan.Zero); }
        catch (UnauthorizedAccessException) { return new(HeadlessEnrollmentExit.Refused, "enroll_lock_untrusted"); }
        return lease is null ? new(HeadlessEnrollmentExit.Unavailable, "enroll_in_progress") : null;
    }

    private static string Hint(int exit) => exit switch
    {
        HeadlessEnrollmentExit.NewProofRequired => " Request a new proof.",
        HeadlessEnrollmentExit.WrongBackend => " Check the backend URL.",
        _ => "",
    };

    private static async Task<HeadlessEnrollmentResult> RunCoreAsync(
        string rawProof, bool fromInstaller, bool installService, IHeadlessHost host, TextWriter stdout, IAgentLogger log, CancellationToken ct)
    {
        var serviceState = host.GetServiceState();
        // Paused or stopping service: activation cannot start it, so keep the one-time proof unspent.
        if (serviceState == HeadlessServiceState.Other)
            return new(HeadlessEnrollmentExit.Unavailable, "service_not_ready");
#if CERBERUS_SERVER_PROFILE
        // The server profile never installs a service; it only starts or notifies the MSI-installed one.
        if (serviceState == HeadlessServiceState.NotInstalled)
            return new(HeadlessEnrollmentExit.BadInput, "service_not_installed");
        const bool userScope = false;
#else
        var userScope = serviceState == HeadlessServiceState.NotInstalled;
#endif

        string? backend;
        try { backend = host.ResolveBackendUrl(); }
        catch (InvalidOperationException) { return new(HeadlessEnrollmentExit.BadInput, "backend_not_allowed"); }
        if (string.IsNullOrWhiteSpace(backend))
            return new(HeadlessEnrollmentExit.BadInput, "backend_not_configured");

        var loaded = await EnrollHeadlessState.LoadAsync(host, serviceState != HeadlessServiceState.NotInstalled, log, ct).ConfigureAwait(false);
        if (loaded is not var (state, hasCredentials))
            return new(HeadlessEnrollmentExit.Refused, "state_unreadable");

        await DiscardStalePendingAsync(host, log, ct).ConfigureAwait(false);

        // Last check before the proof is sent: the service can be stopped from outside while the cleanup wait runs.
        if (EnrollHeadlessState.ServiceNotReady(host, serviceState, state, hasCredentials) is { } notReady)
            return new(HeadlessEnrollmentExit.Unavailable, notReady);

        var oldFingerprint = host.ReadFingerprintLine();
        using var http = host.CreateHttpClient(new Uri(backend));
        var result = await new HeadlessEnrollment(http, log: log)
            .RunAsync(rawProof, host.BuildOptions(backend), state, hasCredentials, host.OpenDestination(userScope), ct)
            .ConfigureAwait(false);
        if (!result.Succeeded)
            return result;

        try
        {
            var failure = await ActivateAsync(host, userScope, fromInstaller, installService, ct).ConfigureAwait(false);
            if (failure is not null)
            {
                log.Error($"Enrolled credentials were not activated ({failure}).");
                await DiscardPendingAsync(host, log).ConfigureAwait(false);
                return new(HeadlessEnrollmentExit.NewProofRequired, failure);
            }
        }
        catch (Exception ex)
        {
            // Cancellation counts as a failure too (the proof is spent), unless the service already committed the adoption.
            if (ex is OperationCanceledException && await EnrollHeadlessState.AdoptionCommittedAsync(host, state, log).ConfigureAwait(false))
            {
                log.Warn("Enrollment adoption was committed before the run was cancelled.");
                ct = CancellationToken.None;
            }
            else
            {
                log.Error($"Enrolled credentials were not activated ({ex.GetType().Name}).");
                await DiscardPendingAsync(host, log).ConfigureAwait(false);
                return new(HeadlessEnrollmentExit.NewProofRequired, "activation_failed");
            }
        }

        var line = HeadlessEnrollment.FormatFingerprintLine(result.Fingerprint!);
        stdout.WriteLine(line);
        log.Info(line);
        if (oldFingerprint is not null && !string.Equals(oldFingerprint, line, StringComparison.Ordinal))
            log.Info($"Agent key fingerprint replaced old={oldFingerprint["Agent key fingerprint=".Length..]} new={result.Fingerprint}");
        try { host.WriteFingerprintFile(line + "\n" + "agent_id=" + result.Identity!.AgentId + "\n"); }
#if CERBERUS_SERVER_PROFILE
        catch (Exception ex)
#else
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
#endif
        {
            // Server: the credentials are already active; a diagnostic file must not turn this into a failed run.
            log.Warn($"Fingerprint file could not be written ({ex.GetType().Name}).");
        }
        await host.WriteTenantContextAsync(result.Identity!, result.TenantName, ct).ConfigureAwait(false);
        return result;
    }

    // Server profile: the installer rolls back on a non-zero exit, so staged credentials and the adopt marker must not outlive it.
    private static async Task DiscardPendingAsync(IHeadlessHost host, IAgentLogger log)
    {
#if CERBERUS_SERVER_PROFILE
        try
        {
            // Own token: the run token may be the reason activation failed.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await host.DiscardPendingEnrollmentAsync(cleanup.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log.Error($"Pending enrollment could not be removed ({ex.GetType().Name}).");
        }
#else
        _ = host;
        _ = log;
        await Task.CompletedTask.ConfigureAwait(false);
#endif
    }

    // A killed earlier run can leave staged credentials behind. Best effort: the new run overwrites them anyway.
    private static async Task DiscardStalePendingAsync(IHeadlessHost host, IAgentLogger log, CancellationToken ct)
    {
        try
        {
            if (await host.DiscardStalePendingEnrollmentAsync(ct).ConfigureAwait(false))
                log.Warn("Stale pending enrollment credentials were removed.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Warn($"Stale pending enrollment could not be removed ({ex.GetType().Name}).");
        }
    }

    private static async Task<string?> ActivateAsync(IHeadlessHost host, bool userScope, bool fromInstaller, bool installService, CancellationToken ct)
    {
#if !CERBERUS_SERVER_PROFILE
        if (userScope)
        {
            // No service yet: credentials sit in the user store, exactly as after --register.
            if (installService)
                host.InstallDesktopService();
            return null;
        }
#else
        _ = userScope;
        _ = installService;
#endif
        // The installer commits directly only while the service is not running; everyone else needs it up.
        var state = await host.EnsureRunningAsync(startIfStopped: !fromInstaller, ct).ConfigureAwait(false);
        if (state == HeadlessServiceState.Running)
            return await host.ActivateAsync(commitDirectly: false, ct).ConfigureAwait(false);
        if (fromInstaller && state == HeadlessServiceState.Stopped)
            return await host.ActivateAsync(commitDirectly: true, ct).ConfigureAwait(false);
        return "service_not_running";
    }

    private static string? ReadInstallerValue(string[] args)
    {
        const string Key = "--proof-from-installer";
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg is null)
                continue;
            if (arg.StartsWith(Key + "=", StringComparison.OrdinalIgnoreCase))
                return arg[(Key.Length + 1)..].Trim('"');
            if (string.Equals(arg, Key, StringComparison.OrdinalIgnoreCase))
                return i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[i + 1].Trim('"') : null;
        }
        return null;
    }

    private static string? ReadFile(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return ReadBounded(stream);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    private static async Task<string?> ReadStdinAsync(CancellationToken ct)
    {
        // A WinExe only has a stdin when the caller redirects one; otherwise this fails fast.
        if (!Console.IsInputRedirected)
            return null;
        try
        {
            return await Task.Run(() => ReadBounded(Console.OpenStandardInput()), ct)
                .WaitAsync(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string? ReadBounded(Stream stream)
    {
        var buffer = new byte[HeadlessEnrollmentProof.MaxSourceBytes + 1];
        var read = 0;
        while (read < buffer.Length)
        {
            var n = stream.Read(buffer, read, buffer.Length - read);
            if (n == 0)
                break;
            read += n;
        }
        return read is 0 or > HeadlessEnrollmentProof.MaxSourceBytes ? null : Encoding.UTF8.GetString(buffer, 0, read);
    }
}
