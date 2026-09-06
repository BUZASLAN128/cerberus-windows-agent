using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Cerberus.Agent.Core;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Installer.Helper;

/// <summary>MSI transaction actions, extracted from the signed package. No network, credential, RDP or Tailscale operations.</summary>
internal static class Program
{
    private const string ServiceName = "CerberusAgent";
    private sealed record Snapshot(string ImagePath, uint StartType, uint State, bool DelayedAutoStart, DateTimeOffset CapturedUtc, bool Completed = false);

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (!AgentUpdateSecurity.IsLocalSystem() || args.Length != 6 || !Guid.TryParse(args[1], out var product))
                return 2;
            var operation = args[0];
            if (operation is not ("capture" or "configure" or "stop" or "restore" or "health" or "commit"))
                return 2;
            var root = Path.Combine(AgentUpdateSecurity.DefaultPrivilegedRoot, "installer-transactions");
            AgentUpdateSecurity.EnsureProtectedRoot(root);
            var snapshotPath = Path.Combine(root, product.ToString("N") + ".json");
            using var manager = OpenSCManager(null, null, 1);
            ThrowIfInvalid(manager);
            using var service = OpenService(manager, ServiceName, 0x77);
            ThrowIfInvalid(service);
            switch (operation)
            {
                case "capture":
                    var existing = AgentUpdateDurableFile.Read<Snapshot>(snapshotPath, root);
                    if (existing is not null && !existing.Completed)
                        throw new InvalidOperationException("An unfinished installer transaction requires recovery.");
                    AgentUpdateDurableFile.Write(snapshotPath, root, Capture(service));
                    break;
                case "stop":
                    Stop(service);
                    break;
                case "restore":
                    var before = AgentUpdateDurableFile.Read<Snapshot>(snapshotPath, root);
                    // A failure before capture performed no forward mutation.
                    if (before is null) return 0;
                    Stop(service);
                    Configure(service, before.ImagePath, before.StartType, before.DelayedAutoStart);
                    if (before.State is 4 or 7)
                    {
                        Start(service);
                        if (before.State == 7)
                        {
                            Check(ControlService(service, 2, out _));
                            WaitForState(service, 7);
                        }
                    }
                    AgentUpdateDurableFile.Write(snapshotPath, root, before with { Completed = true });
                    break;
                case "configure":
                    var captured = AgentUpdateDurableFile.Read<Snapshot>(snapshotPath, root)
                        ?? throw new InvalidOperationException("SCM rollback snapshot is missing.");
                    var executable = Path.Combine(Path.GetFullPath(args[2]), "Cerberus.Agent.Service.exe");
                    AgentUpdateSecurity.ValidateTrustedPath(executable, Path.GetFullPath(args[2]), allowMissing: false);
                    Configure(service, "\"" + executable + "\"", captured.StartType, captured.DelayedAutoStart);
                    Start(service);
                    break;
                case "health":
                    await VerifyHealthAsync(service, args[2], args[3], args[4], args[5],
                        Path.Combine(root, product.ToString("N") + ".health-failure.json"), root).ConfigureAwait(false);
                    break;
                case "commit":
                    var committed = AgentUpdateDurableFile.Read<Snapshot>(snapshotPath, root)
                        ?? throw new InvalidOperationException("SCM rollback snapshot is missing.");
                    AgentUpdateDurableFile.Write(snapshotPath, root, committed with { Completed = true });
                    break;
            }
            return 0;
        }
        catch (Exception ex)
        {
            // MSI logs contain only a stable diagnostic category, never exception paths or configuration.
            Console.Error.WriteLine("Cerberus installer action failed: " + ex.GetType().Name);
            return 1603;
        }
    }

    private static Snapshot Capture(ServiceHandle service)
    {
        QueryServiceConfig(service, IntPtr.Zero, 0, out var bytes);
        if (bytes is <= 0 or > 64 * 1024) throw new InvalidOperationException("SCM configuration length is invalid.");
        var memory = Marshal.AllocHGlobal((int)bytes);
        try
        {
            Check(QueryServiceConfig(service, memory, bytes, out _));
            var config = Marshal.PtrToStructure<ServiceConfig>(memory);
            var state = Status(service).CurrentState;
            if (state is not (1 or 4 or 7)) throw new InvalidOperationException("SCM state is changing.");
            var delayed = new DelayedAutoStart();
            Check(QueryServiceConfig2(service, 3, ref delayed, (uint)Marshal.SizeOf<DelayedAutoStart>(), out _));
            return new Snapshot(Marshal.PtrToStringUni(config.BinaryPath) ?? throw new InvalidOperationException("SCM path is missing."),
                config.StartType, state, delayed.Enabled != 0, DateTimeOffset.UtcNow);
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    private static void Configure(ServiceHandle service, string path, uint startType, bool delayed)
    {
        Check(ChangeServiceConfig(service, uint.MaxValue, startType, uint.MaxValue, path, null, IntPtr.Zero, null, null, null, null));
        var delayedInfo = new DelayedAutoStart { Enabled = delayed ? 1 : 0 };
        Check(ChangeServiceConfig2(service, 3, ref delayedInfo));
    }

    private static void Stop(ServiceHandle service)
    {
        var status = Status(service);
        if (status.CurrentState == 1) return;
        if (status.CurrentState != 3) Check(ControlService(service, 1, out _));
        WaitForState(service, 1);
    }

    private static void Start(ServiceHandle service)
    {
        if (Status(service).CurrentState == 4) return;
        Check(StartService(service, 0, IntPtr.Zero));
        WaitForState(service, 4);
    }

    private static void WaitForState(ServiceHandle service, uint state)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < TimeSpan.FromSeconds(45))
        {
            if (Status(service).CurrentState == state) return;
            Thread.Sleep(100);
        }
        throw new InvalidOperationException("SCM transition timed out.");
    }

    private static ServiceStatusProcess Status(ServiceHandle service)
    {
        var value = new ServiceStatusProcess();
        Check(QueryServiceStatusEx(service, 0, ref value, Marshal.SizeOf<ServiceStatusProcess>(), out _));
        return value;
    }

    private static async Task VerifyHealthAsync(ServiceHandle service, string runtime, string expectedVersion, string executableHash, string assemblyHash,
        string diagnosticPath, string diagnosticRoot)
    {
        var phase = AgentInstallerHealthPhase.RuntimePath;
        string? observedVersion = null;
        uint? serviceProcessId = null;
        uint? pipeProcessId = null;
        bool? responseSuccess = null;
        try
        {
            runtime = Path.GetFullPath(runtime);
            var executable = Path.Combine(runtime, "Cerberus.Agent.Service.exe");
            var assembly = Path.Combine(runtime, "Cerberus.Agent.Service.dll");
            phase = AgentInstallerHealthPhase.ServiceExecutableHash;
            VerifyHash(executable, runtime, executableHash);
            phase = AgentInstallerHealthPhase.ServiceAssemblyHash;
            VerifyHash(assembly, runtime, assemblyHash);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            while (true)
            {
                timeout.Token.ThrowIfCancellationRequested();
                phase = AgentInstallerHealthPhase.ServiceState;
                observedVersion = null;
                serviceProcessId = null;
                pipeProcessId = null;
                responseSuccess = null;
                var status = Status(service);
                serviceProcessId = status.ProcessId;
                if (status.CurrentState == 4 && status.ProcessId != 0)
                {
                    try
                    {
                        phase = AgentInstallerHealthPhase.ServiceImage;
                        using var process = Process.GetProcessById((int)status.ProcessId);
                        if (!string.Equals(process.MainModule?.FileName, executable, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidOperationException("SCM process image identity mismatch.");
                        phase = AgentInstallerHealthPhase.PipeConnect;
                        using var pipe = new NamedPipeClientStream(".", AgentLocalControlProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                        await pipe.ConnectAsync(1000, timeout.Token).ConfigureAwait(false);
                        phase = AgentInstallerHealthPhase.PipeAuthority;
                        Check(GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var pipeProcess));
                        pipeProcessId = pipeProcess;
                        if (pipeProcess != status.ProcessId)
                            throw new InvalidOperationException("Local health pipe authority mismatch.");
                        phase = AgentInstallerHealthPhase.StatusRequest;
                        await AgentLocalControlProtocol.WriteAsync(pipe, new AgentLocalControlRequest("status"), timeout.Token).ConfigureAwait(false);
                        phase = AgentInstallerHealthPhase.StatusResponse;
                        var response = await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(pipe, timeout.Token).ConfigureAwait(false);
                        observedVersion = response.CurrentVersion;
                        responseSuccess = response.Success;
                        phase = AgentInstallerHealthPhase.ResponseSuccess;
                        if (!response.Success)
                            throw new InvalidOperationException("Installed build readiness mismatch.");
                        phase = AgentInstallerHealthPhase.ResponseVersion;
                        if (!string.Equals(response.CurrentVersion, expectedVersion, StringComparison.Ordinal))
                            throw new InvalidOperationException("Installed build readiness mismatch.");
                        var lifecyclePath = Path.Combine(Path.GetDirectoryName(AgentUpdateSecurity.DefaultPrivilegedRoot)!, "lifecycle-state.json");
                        phase = AgentInstallerHealthPhase.LifecycleAuthority;
                        AgentUpdateSecurity.ValidateTrustedPath(lifecyclePath, Path.GetDirectoryName(lifecyclePath)!, allowMissing: false);
                        phase = AgentInstallerHealthPhase.LifecycleOpen;
                        using var lifecycle = File.OpenRead(lifecyclePath);
                        phase = AgentInstallerHealthPhase.LifecycleLength;
                        if (lifecycle.Length is <= 0 or > 16 * 1024)
                            throw new InvalidOperationException("Lifecycle state is not readable.");
                        phase = AgentInstallerHealthPhase.LifecycleJson;
                        using var document = JsonDocument.Parse(lifecycle);
                        phase = AgentInstallerHealthPhase.LifecycleState;
                        if (!document.RootElement.TryGetProperty("state", out var state) || state.ValueKind != JsonValueKind.String)
                            throw new InvalidOperationException("Lifecycle state is not readable.");
                        return;
                    }
                    catch (TimeoutException) { }
                    catch (IOException) { }
                }
                await Task.Delay(100, timeout.Token).ConfigureAwait(false);
            }
        }
        catch (Exception error)
        {
            try
            {
                AgentUpdateDurableFile.Write(diagnosticPath, diagnosticRoot, AgentInstallerHealthDiagnostic.Capture(
                    phase, error, expectedVersion, observedVersion, serviceProcessId, pipeProcessId, responseSuccess));
            }
            catch (Exception)
            {
                // Diagnostics cannot weaken the health failure or replace the original exception.
            }
            throw;
        }
    }

    private static void VerifyHash(string path, string root, string expected)
    {
        if (expected.Length != 64 || !expected.All(Uri.IsHexDigit))
            throw new InvalidOperationException("Package service identity is missing.");
        AgentUpdateSecurity.ValidateTrustedPath(path, root, allowMissing: false);
        using var stream = File.OpenRead(path);
        if (!Convert.ToHexString(SHA256.HashData(stream)).Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Package service identity mismatch.");
    }

    private static void Check(bool success)
    {
        if (!success) throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    private static void ThrowIfInvalid(ServiceHandle handle)
    {
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }
    [StructLayout(LayoutKind.Sequential)] private struct DelayedAutoStart { public int Enabled; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceConfig
    {
        public uint ServiceType, StartType, ErrorControl;
        public IntPtr BinaryPath, LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies, StartName, DisplayName;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatusProcess
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ServiceHandle OpenService(ServiceHandle manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryServiceConfig(ServiceHandle service, IntPtr configuration, uint size, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryServiceConfig2(ServiceHandle service, uint level, ref DelayedAutoStart info, uint size, out uint needed);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ChangeServiceConfig(ServiceHandle service, uint type, uint startType, uint errorControl, string path, string? group, IntPtr tag, string? dependencies, string? account, string? password, string? displayName);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ChangeServiceConfig2(ServiceHandle service, uint level, ref DelayedAutoStart info);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool StartService(ServiceHandle service, uint count, IntPtr args);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool ControlService(ServiceHandle service, uint code, out ServiceStatus status);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, ref ServiceStatusProcess status, int size, out int needed);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}
