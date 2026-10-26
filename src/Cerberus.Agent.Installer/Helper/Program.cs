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
internal static partial class Program
{
    private const string ServiceName = AgentInstallIdentity.ServiceName;
    // OpenService reports an optional service absence only with this exact SCM code.
    // Access denied and every other SCM error must remain a hard installer failure.
    private const int ErrorServiceDoesNotExist = 1060; // ERROR_SERVICE_DOES_NOT_EXIST
    private sealed record Snapshot(string? ImagePath, uint StartType, uint State, bool DelayedAutoStart, DateTimeOffset CapturedUtc, bool Completed = false)
    {
        // Older transaction records predate the marker and therefore describe a
        // captured, present service. New app-only upgrades persist false explicitly.
        public bool ServicePresent { get; init; } = true;
    }

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (!AgentUpdateSecurity.IsLocalSystem() || args.Length is not (6 or 7) || !Guid.TryParse(args[1], out var product))
                return 2;
            var operation = args[0];
            if (operation is not ("bootstrap" or "capture" or "configure" or "stop" or "restore" or "health" or "commit" or "ensure-running"))
                return 2;
            // The optional seventh argument belongs to health: only "1" requires backend contact; any other value is off.
            if (args.Length == 7 && operation != "health")
                return 2;
            if (operation == "bootstrap")
            {
                // Fresh MSI installs have no service yet. Establish authority before the UI can write machine data.
                // Existing namespaces pass the same provenance gate; bootstrap never repairs or resets them.
                AgentUpdateSecurity.EnsureProtectedRoot(AgentUpdateSecurity.DefaultPrivilegedRoot);
                return 0;
            }
            var root = Path.Combine(AgentUpdateSecurity.DefaultPrivilegedRoot, "installer-transactions");
            AgentUpdateSecurity.EnsureProtectedRoot(root);
            var snapshotPath = Path.Combine(root, product.ToString("N") + ".json");
            var diagnosticPath = Path.Combine(root, product.ToString("N") + ".health-failure.json");

            if (operation == "ensure-running")
            {
                // Rollback safety net for the server MSI: leave the previous service running. Never stops or reconfigures.
                if (!AgentBuildProfile.IsServer) return 2;
                using var ensureManager = OpenSCManager(null, null, 1);
                ThrowIfInvalid(ensureManager);
                using var ensureService = OpenExistingService(ensureManager) ?? throw new Win32Exception(ErrorServiceDoesNotExist);
                // A stop in progress finishes first; Start on a StopPending service would fail.
                if (Status(ensureService).CurrentState == 3) WaitForState(ensureService, 1, TimeSpan.FromSeconds(60));
                if (Status(ensureService).CurrentState == 2) WaitForState(ensureService, 4, TimeSpan.FromSeconds(60));
                else Start(ensureService, TimeSpan.FromSeconds(60));
                return 0;
            }

            if (operation == "health" && AgentBuildProfile.IsServer)
            {
                // WiX owns the server service, so there is no SCM capture snapshot to require or complete.
                using var serverManager = OpenSCManager(null, null, 1);
                ThrowIfInvalid(serverManager);
                using var serverService = OpenExistingService(serverManager) ?? throw new Win32Exception(ErrorServiceDoesNotExist);
                await VerifyHealthAsync(serverService, args[2], args[3], args[4], args[5], diagnosticPath, root,
                    HealthOptions.Server(args.Length == 7 && args[6] == "1")).ConfigureAwait(false);
                return 0;
            }

            var snapshot = AgentUpdateDurableFile.Read<Snapshot>(snapshotPath, root);
            if (operation == "capture")
            {
                if (snapshot is not null && !snapshot.Completed)
                    throw new InvalidOperationException("An unfinished installer transaction requires recovery.");
            }
            else
            {
                // A durable absent marker owns this transaction's service scope.
                // Do not reopen SCM here: a service created concurrently (for
                // example by enrollment) must not be adopted or started by MSI.
                if (snapshot is not null && !snapshot.ServicePresent)
                {
                    if (operation is ("restore" or "health" or "commit"))
                    {
                        // No service mutation occurred for an absent snapshot; after
                        // rollback/health reaches this checkpoint, the transaction
                        // has no forward state left that could require restoration.
                        CompleteSnapshot(snapshotPath, root, snapshot);
                    }
                    return 0;
                }

                // Rollback may run before capture was committed. There was no
                // service mutation to undo, so it must remain a no-op.
                if (snapshot is null && operation is ("restore" or "stop"))
                    return 0;
                if (snapshot is null && operation is ("configure" or "health" or "commit"))
                    throw new InvalidOperationException("SCM rollback snapshot is missing.");
                if (snapshot is not null && snapshot.ServicePresent && string.IsNullOrWhiteSpace(snapshot.ImagePath))
                    throw new InvalidOperationException("SCM rollback snapshot is invalid.");
            }

            using var manager = OpenSCManager(null, null, 1);
            ThrowIfInvalid(manager);
            using var service = OpenExistingService(manager);
            if (service is null)
            {
                if (operation == "capture" && (snapshot is null || !snapshot.ServicePresent))
                {
                    AgentUpdateDurableFile.Write(snapshotPath, root, CreateAbsentSnapshot());
                    return 0;
                }

                // A present snapshot losing its service is not equivalent to an
                // app-only upgrade. Preserve the failure instead of silently
                // skipping rollback, repair, or health verification.
                throw new Win32Exception(ErrorServiceDoesNotExist);
            }

            switch (operation)
            {
                case "capture":
                    AgentUpdateDurableFile.Write(snapshotPath, root, Capture(service));
                    break;
                case "stop":
                    Stop(service);
                    break;
                case "restore":
                    var before = snapshot ?? throw new InvalidOperationException("SCM rollback snapshot is missing.");
                    var imagePath = before.ImagePath ?? throw new InvalidOperationException("SCM rollback snapshot is invalid.");
                    Stop(service);
                    Configure(service, imagePath, before.StartType, before.DelayedAutoStart);
                    if (before.State is 4 or 7)
                    {
                        Start(service);
                        if (before.State == 7)
                        {
                            Check(ControlService(service, 2, out _));
                            WaitForState(service, 7);
                        }
                    }
                    CompleteSnapshot(snapshotPath, root, before);
                    break;
                case "configure":
                    var captured = snapshot
                        ?? throw new InvalidOperationException("SCM rollback snapshot is missing.");
                    var executable = Path.Combine(Path.GetFullPath(args[2]), "Cerberus.Agent.Service.exe");
                    AgentUpdateSecurity.ValidateTrustedPath(executable, Path.GetFullPath(args[2]), allowMissing: false);
                    Configure(service, "\"" + executable + "\"", captured.StartType, captured.DelayedAutoStart);
                    Start(service);
                    break;
                case "health":
                    await VerifyHealthAsync(service, args[2], args[3], args[4], args[5], diagnosticPath, root, HealthOptions.Desktop).ConfigureAwait(false);
                    break;
                case "commit":
                    var committed = snapshot
                        ?? throw new InvalidOperationException("SCM rollback snapshot is missing.");
                    CompleteSnapshot(snapshotPath, root, committed);
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

    private static Snapshot CreateAbsentSnapshot()
        => new(null, 0, 1, false, DateTimeOffset.UtcNow)
        {
            ServicePresent = false,
        };

    private static void CompleteSnapshot(string snapshotPath, string root, Snapshot snapshot)
    {
        if (!snapshot.Completed)
            AgentUpdateDurableFile.Write(snapshotPath, root, snapshot with { Completed = true });
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
                config.StartType, state, delayed.Enabled != 0, DateTimeOffset.UtcNow)
            {
                ServicePresent = true,
            };
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    private static ServiceHandle? OpenExistingService(ServiceHandle manager)
    {
        var service = OpenService(manager, ServiceName, 0x77);
        if (!service.IsInvalid)
            return service;

        var error = Marshal.GetLastWin32Error();
        service.Dispose();
        if (error == ErrorServiceDoesNotExist)
            return null;
        throw new Win32Exception(error);
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

    private static void Start(ServiceHandle service, TimeSpan? wait = null)
    {
        if (Status(service).CurrentState == 4) return;
        Check(StartService(service, 0, IntPtr.Zero));
        WaitForState(service, 4, wait);
    }

    private static void WaitForState(ServiceHandle service, uint state, TimeSpan? limit = null)
    {
        var deadline = Stopwatch.StartNew();
        while (deadline.Elapsed < (limit ?? TimeSpan.FromSeconds(45)))
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
