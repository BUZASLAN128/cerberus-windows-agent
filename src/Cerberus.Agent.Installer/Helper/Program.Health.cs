using System.Diagnostics;
using System.IO.Pipes;
using System.Text.Json;
using Cerberus.Agent.Core;
using Microsoft.Win32;

namespace Cerberus.Agent.Installer.Helper;

internal static partial class Program
{
    /// <summary>Desktop keeps the single readiness pass. Server adds the stability window, optional backend contact and a 5 minute cap.</summary>
    private sealed record HealthOptions(TimeSpan Overall, TimeSpan Stability, bool RequireBackend, bool AllowPendingReboot)
    {
        public static readonly HealthOptions Desktop = new(TimeSpan.FromSeconds(60), TimeSpan.Zero, false, false);
        private static readonly TimeSpan BackendWindow = TimeSpan.FromMinutes(3);
        public static HealthOptions Server(bool requireBackend)
            => new(TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(60), requireBackend, true);
        public TimeSpan SettleLimit => RequireBackend ? BackendWindow : Stability + TimeSpan.FromSeconds(30);
    }

    private sealed class HealthTrace
    {
        public AgentInstallerHealthPhase Phase = AgentInstallerHealthPhase.RuntimePath;
        public string? ObservedVersion;
        public uint? ServiceProcessId;
        public uint? PipeProcessId;
        public bool? ResponseSuccess;
    }

    private static async Task VerifyHealthAsync(ServiceHandle service, string runtime, string expectedVersion, string executableHash, string assemblyHash,
        string diagnosticPath, string diagnosticRoot, HealthOptions options)
    {
        var trace = new HealthTrace();
        try
        {
            runtime = Path.GetFullPath(runtime);
            try
            {
                await VerifyRuntimeAsync(service, runtime, expectedVersion, executableHash, assemblyHash, options, trace).ConfigureAwait(false);
            }
            catch (Exception) when (options.AllowPendingReboot && PendingRenameUnder(runtime))
            {
                // The new files replace the running ones at the next restart, so this process cannot be judged now.
                Console.Error.WriteLine("Cerberus installer health skipped: a restart is pending for the application folder.");
            }
        }
        catch (Exception error)
        {
            try
            {
                AgentUpdateDurableFile.Write(diagnosticPath, diagnosticRoot, AgentInstallerHealthDiagnostic.Capture(
                    trace.Phase, error, expectedVersion, trace.ObservedVersion, trace.ServiceProcessId, trace.PipeProcessId, trace.ResponseSuccess));
            }
            catch (Exception)
            {
                // Diagnostics cannot weaken the health failure or replace the original exception.
            }
            throw;
        }
    }

    private static async Task VerifyRuntimeAsync(ServiceHandle service, string runtime, string expectedVersion, string executableHash, string assemblyHash,
        HealthOptions options, HealthTrace trace)
    {
        var executable = Path.Combine(runtime, "Cerberus.Agent.Service.exe");
        var assembly = Path.Combine(runtime, "Cerberus.Agent.Service.dll");
        trace.Phase = AgentInstallerHealthPhase.ServiceExecutableHash;
        VerifyHash(executable, runtime, executableHash);
        trace.Phase = AgentInstallerHealthPhase.ServiceAssemblyHash;
        VerifyHash(assembly, runtime, assemblyHash);
        using var overall = new CancellationTokenSource(options.Overall);
        using var first = CancellationTokenSource.CreateLinkedTokenSource(overall.Token);
        first.CancelAfter(TimeSpan.FromSeconds(60));
        uint healthyProcessId;
        while (true)
        {
            first.Token.ThrowIfCancellationRequested();
            trace.Phase = AgentInstallerHealthPhase.ServiceState;
            trace.ObservedVersion = null;
            trace.ServiceProcessId = null;
            trace.PipeProcessId = null;
            trace.ResponseSuccess = null;
            var status = Status(service);
            trace.ServiceProcessId = status.ProcessId;
            if (status.CurrentState == 4 && status.ProcessId != 0)
            {
                try
                {
                    await ProbeAsync(status, executable, expectedVersion, trace, options.Stability > TimeSpan.Zero, first.Token).ConfigureAwait(false);
                    VerifyLifecycleState(trace);
                    healthyProcessId = status.ProcessId;
                    break;
                }
                catch (TimeoutException) { }
                catch (IOException) { }
            }
            await Task.Delay(100, first.Token).ConfigureAwait(false);
        }
        if (options.Stability == TimeSpan.Zero)
            return;

        // The service recovery policy restarts a crashed process after 60 s, so a bare "running" state can hide a crash.
        // The same PID must still be running and answering when the stability window ends.
        var healthyFor = Stopwatch.StartNew();
        var stableAnswer = false;
        var backendSeen = false;
        while (true)
        {
            overall.Token.ThrowIfCancellationRequested();
            trace.Phase = AgentInstallerHealthPhase.Stability;
            var status = Status(service);
            trace.ServiceProcessId = status.ProcessId;
            if (status.CurrentState != 4 || status.ProcessId != healthyProcessId)
                throw new InvalidOperationException("Service did not stay running.");
            try
            {
                var response = await ProbeAsync(status, executable, expectedVersion, trace, true, overall.Token).ConfigureAwait(false);
                stableAnswer |= healthyFor.Elapsed >= options.Stability;
                backendSeen |= response.LastBackendContactUtc is not null;
            }
            catch (TimeoutException) { }
            catch (IOException) { }
            if (stableAnswer && (!options.RequireBackend || backendSeen))
                return;
            if (healthyFor.Elapsed > options.SettleLimit)
            {
                trace.Phase = stableAnswer ? AgentInstallerHealthPhase.BackendContact : AgentInstallerHealthPhase.Stability;
                throw new InvalidOperationException(stableAnswer ? "Backend contact was not observed." : "Service did not answer after the stability window.");
            }
            await Task.Delay(TimeSpan.FromSeconds(2), overall.Token).ConfigureAwait(false);
        }
    }

    private static async Task<AgentLocalControlResponse> ProbeAsync(ServiceStatusProcess status, string executable, string expectedVersion,
        HealthTrace trace, bool readiness, CancellationToken ct)
    {
        trace.Phase = AgentInstallerHealthPhase.ServiceImage;
        using var process = Process.GetProcessById((int)status.ProcessId);
        if (!string.Equals(process.MainModule?.FileName, executable, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("SCM process image identity mismatch.");
        trace.Phase = AgentInstallerHealthPhase.PipeConnect;
        using var pipe = new NamedPipeClientStream(".", AgentLocalControlProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(1000, ct).ConfigureAwait(false);
        trace.Phase = AgentInstallerHealthPhase.PipeAuthority;
        Check(GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pipeProcess));
        trace.PipeProcessId = pipeProcess;
        if (pipeProcess != status.ProcessId)
            throw new InvalidOperationException("Local health pipe authority mismatch.");
        trace.Phase = AgentInstallerHealthPhase.StatusRequest;
        await AgentLocalControlProtocol.WriteAsync(pipe, new AgentLocalControlRequest(readiness ? "readiness" : "status"), ct).ConfigureAwait(false);
        trace.Phase = AgentInstallerHealthPhase.StatusResponse;
        var response = await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(pipe, ct).ConfigureAwait(false);
        trace.ObservedVersion = response.CurrentVersion;
        trace.ResponseSuccess = response.Success;
        trace.Phase = AgentInstallerHealthPhase.ResponseSuccess;
        if (!response.Success)
            throw new InvalidOperationException("Installed build readiness mismatch.");
        trace.Phase = AgentInstallerHealthPhase.ResponseVersion;
        if (!string.Equals(response.CurrentVersion, expectedVersion, StringComparison.Ordinal))
            throw new InvalidOperationException("Installed build readiness mismatch.");
        return response;
    }

    private static void VerifyLifecycleState(HealthTrace trace)
    {
        var lifecyclePath = Path.Combine(Path.GetDirectoryName(AgentUpdateSecurity.DefaultPrivilegedRoot)!, "lifecycle-state.json");
        trace.Phase = AgentInstallerHealthPhase.LifecycleAuthority;
        AgentUpdateSecurity.ValidateTrustedPath(lifecyclePath, Path.GetDirectoryName(lifecyclePath)!, allowMissing: false);
        trace.Phase = AgentInstallerHealthPhase.LifecycleOpen;
        using var lifecycle = File.OpenRead(lifecyclePath);
        trace.Phase = AgentInstallerHealthPhase.LifecycleLength;
        if (lifecycle.Length is <= 0 or > 16 * 1024)
            throw new InvalidOperationException("Lifecycle state is not readable.");
        trace.Phase = AgentInstallerHealthPhase.LifecycleJson;
        using var document = JsonDocument.Parse(lifecycle);
        trace.Phase = AgentInstallerHealthPhase.LifecycleState;
        if (!document.RootElement.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException("Lifecycle state is not readable.");
    }

    /// <summary>True when a queued rename/delete (PendingFileRenameOperations) targets a path under the runtime folder.</summary>
    private static bool PendingRenameUnder(string runtime)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager", writable: false);
            if (key?.GetValue("PendingFileRenameOperations") is not string[] entries)
                return false;
            var prefix = runtime.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return entries.Any(entry => entry.TrimStart('!').Replace(@"\??\", "", StringComparison.Ordinal)
                .StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception)
        {
            return false;
        }
    }
}
