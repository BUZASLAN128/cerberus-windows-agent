using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
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
    ISecretStore OpenDestination(bool userScope);
    HttpClient CreateHttpClient(Uri backend);
    /// <summary>Hands the saved pending credentials to the service (<c>false</c>) or commits them directly (<c>true</c>). Null on success, otherwise a code.</summary>
    Task<string?> ActivateAsync(bool commitDirectly, CancellationToken ct);
    string? ReadFingerprintLine();
    void WriteFingerprintFile(string content);
    Task WriteTenantContextAsync(AgentIdentity identity, string? tenantName, CancellationToken ct);
    IAgentLogger OpenLog();
#if !CERBERUS_SERVER_PROFILE
    void InstallDesktopService();
#endif
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

    private static string Hint(int exit) => exit switch
    {
        HeadlessEnrollmentExit.NewProofRequired => " Request a new proof.",
        HeadlessEnrollmentExit.WrongBackend => " Check the backend URL.",
        _ => "",
    };

    private static async Task<HeadlessEnrollmentResult> RunCoreAsync(
        string rawProof, bool fromInstaller, bool installService, IHeadlessHost host, TextWriter stdout, IAgentLogger log, CancellationToken ct)
    {
        if (fromInstaller && !host.IsLocalSystem)
            return new(HeadlessEnrollmentExit.BadInput, "proof_from_installer_requires_local_system");
        if (!host.IsAdministrator)
            return new(HeadlessEnrollmentExit.BadInput, "administrator_required");
        if (!HeadlessEnrollmentProof.TryNormalize(rawProof, out _))
            return new(HeadlessEnrollmentExit.BadInput, "proof_invalid");

        var serviceState = host.GetServiceState();
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

        AgentLifecycleSnapshot state;
        bool hasCredentials;
        try
        {
            state = await host.LoadLifecycleAsync(ct).ConfigureAwait(false);
            hasCredentials = host.HasMachineCredentials();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Error($"Local enrollment state could not be read ({ex.GetType().Name}).");
            return new(HeadlessEnrollmentExit.Refused, "state_unreadable");
        }

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
                return new(HeadlessEnrollmentExit.NewProofRequired, failure);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Error($"Enrolled credentials were not activated ({ex.GetType().Name}).");
            return new(HeadlessEnrollmentExit.NewProofRequired, "activation_failed");
        }

        var line = HeadlessEnrollment.FormatFingerprintLine(result.Fingerprint!);
        stdout.WriteLine(line);
        log.Info(line);
        if (oldFingerprint is not null && !string.Equals(oldFingerprint, line, StringComparison.Ordinal))
            log.Info($"Agent key fingerprint replaced old={oldFingerprint["Agent key fingerprint=".Length..]} new={result.Fingerprint}");
        try { host.WriteFingerprintFile(line + "\n" + "agent_id=" + result.Identity!.AgentId + "\n"); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Warn($"Fingerprint file could not be written ({ex.GetType().Name}).");
        }
        await host.WriteTenantContextAsync(result.Identity!, result.TenantName, ct).ConfigureAwait(false);
        return result;
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

/// <summary>Production host: SCM, control pipe, DPAPI stores and the protected provisioning directory.</summary>
internal sealed class WindowsHeadlessHost : IHeadlessHost
{
    private static readonly Regex FingerprintLine = new(
        "^Agent key fingerprint=sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AgentInstallIdentity.DataDirName);
    private static string FingerprintPath => Path.Combine(DataDirectory, EnrollHeadlessMode.FingerprintFileName);

    public bool IsAdministrator => Elevation.IsAdministrator();
    public bool IsLocalSystem => AgentUpdateSecurity.IsLocalSystem();

    public HeadlessServiceState GetServiceState() => AgentStatus.GetService() switch
    {
        { Installed: false } => HeadlessServiceState.NotInstalled,
        { Text: "stopped" } => HeadlessServiceState.Stopped,
        { Text: "starting" } => HeadlessServiceState.Starting,
        { Text: "running" } => HeadlessServiceState.Running,
        _ => HeadlessServiceState.Other,
    };

    public async Task<HeadlessServiceState> EnsureRunningAsync(bool startIfStopped, CancellationToken ct)
    {
        var state = GetServiceState();
        if (state == HeadlessServiceState.Stopped && startIfStopped)
        {
            try { await Task.Run(ServiceInstaller.StartOrThrow, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or System.ServiceProcess.TimeoutException)
            {
                return GetServiceState();
            }
        }
        for (var i = 0; i < 60 && (state = GetServiceState()) == HeadlessServiceState.Starting; i++)
            await Task.Delay(500, ct).ConfigureAwait(false);
        return state;
    }

    public string? ResolveBackendUrl()
        => BootstrapResolver.ResolveConfiguredBackend(UiConfigStore.LoadMergedWithEnv())?.BackendUrl;

    public HeadlessEnrollmentOptions BuildOptions(string backendUrl) => new(
        backendUrl,
        WindowsDeviceInfo.ComputeDeviceFingerprint(),
        WindowsDeviceInfo.GetAgentVersion(),
        WindowsDeviceInfo.GetBuildId(),
        WindowsDeviceInfo.GetBuildChannel(),
        Environment.MachineName);

    public bool HasMachineCredentials() => File.Exists(DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.Machine));

    public Task<AgentLifecycleSnapshot> LoadLifecycleAsync(CancellationToken ct)
        => new DurableAgentLifecycleStateStore().LoadAsync(ct);

    public ISecretStore OpenDestination(bool userScope)
        => userScope ? new DpapiSecretStore(SecretStoreScope.User) : new PendingCredentialStore();

    // A redirect would replay the proof to another host.
    public HttpClient CreateHttpClient(Uri backend)
        => new(new HttpClientHandler { AllowAutoRedirect = false }) { BaseAddress = backend, Timeout = TimeSpan.FromSeconds(30) };

    public async Task<string?> ActivateAsync(bool commitDirectly, CancellationToken ct)
    {
        if (commitDirectly)
            return await CommitDirectlyAsync(ct).ConfigureAwait(false);

        string? code = null;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            // The marker binds the lifecycle generation, which can move while the service finishes starting.
            using (await AgentUpdateLaunchFence.AcquireForEnrollmentPromotionAsync(ct).ConfigureAwait(false))
            {
                var lifecycle = await new DurableAgentLifecycleStateStore().LoadAsync(ct).ConfigureAwait(false);
                AgentCredentialPublication.RequireNoUnresolvedPublication();
                await AgentEnrollmentPromotion.WriteAsync(lifecycle.Generation, AgentEnrollmentPromotion.OpenPendingStore(), ct)
                    .ConfigureAwait(false);
            }
            var response = await AgentLocalControlClient.SendAsync(new("enrollment-adopt"), ct).ConfigureAwait(false);
            if (response.Success)
                return null;
            code = response.Code;
            if (code is not ("enrollment_proof_required" or "enrollment_proof_stale" or "recovery_busy"))
                break;
            await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
        }
        return code ?? "adopt_failed";
    }

    // LocalSystem with the service stopped: the same checks and commit the service runs for enrollment-adopt.
    private static async Task<string?> CommitDirectlyAsync(CancellationToken ct)
    {
        using var fence = await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false);
        var durable = new DurableAgentLifecycleStateStore();
        var current = await durable.LoadAsync(ct).ConfigureAwait(false);
        if (!current.QuiescenceComplete || current.ReasonCode == AgentLifecycleStatePolicy.AgentRevokedCode)
            return "state_refused";
        AgentCredentialPublication.RequireNoUnresolvedPublication();
        var pending = AgentEnrollmentPromotion.OpenPendingStore();
        await AgentEnrollmentPromotion.WriteAsync(current.Generation, pending, ct).ConfigureAwait(false);
        var marker = await AgentEnrollmentPromotion.ReadAsync(ct).ConfigureAwait(false);
        if (marker is null || !await AgentEnrollmentPromotion.MatchesAsync(marker, pending, ct).ConfigureAwait(false))
            return "enrollment_identity_mismatch";
        await durable.CommitEnrollmentAsync(current.Generation, marker.Nonce,
            cancel => AgentCredentialPublication.BeginAsync(durable, current.Generation, marker.Nonce, cancel), ct).ConfigureAwait(false);
        return null;
    }

    public string? ReadFingerprintLine()
    {
        try
        {
            using var reader = new StreamReader(FingerprintPath, Encoding.UTF8);
            var first = reader.ReadLine()?.Trim();
            return first is not null && FingerprintLine.IsMatch(first) ? first : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void WriteFingerprintFile(string content)
    {
        Directory.CreateDirectory(DataDirectory);
        var temporary = FingerprintPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, content, new UTF8Encoding(false));
            File.Move(temporary, FingerprintPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    public Task WriteTenantContextAsync(AgentIdentity identity, string? tenantName, CancellationToken ct)
        => AgentUiContextStore.WriteBestEffortAsync(identity, tenantName, accountLabel: null, ct);

    public IAgentLogger OpenLog()
    {
        try { return AgentFileLogger.CreateService(alsoConsole: false); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return NullAgentLogger.Instance;
        }
    }

#if !CERBERUS_SERVER_PROFILE
    public void InstallDesktopService() => AgentServiceProvisioning.InstallOrThrow();
#endif

    /// <summary>Stages credentials in the protected pending directory; the service (or the installer) commits them.</summary>
    private sealed class PendingCredentialStore : ISecretStore
    {
        public async Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
            string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
        {
            using var fence = await AgentUpdateLaunchFence.AcquireForEnrollmentPromotionAsync(ct).ConfigureAwait(false);
            AgentCredentialPublication.RequireNoUnresolvedPublication();
            await AgentEnrollmentPromotion.OpenPendingStore()
                .SaveAsync(identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey, ct)
                .ConfigureAwait(false);
        }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => AgentEnrollmentPromotion.OpenPendingStore().LoadAsync(ct);

        public Task ClearAsync(CancellationToken ct) => throw new InvalidOperationException("Pending enrollment cannot be cleared here.");
    }
}
