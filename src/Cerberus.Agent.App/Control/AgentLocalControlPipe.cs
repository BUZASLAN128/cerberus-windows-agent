using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Cerberus.Agent.Core;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.App.Control;

internal static class AgentLocalControlClient
{
    public static async Task<AgentLocalControlResponse> SendAsync(AgentLocalControlRequest request, CancellationToken ct)
    {
        if (!AgentLocalControlProtocol.IsAllowed(request, privileged: true))
            return new(false, "invalid_request");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(45));
        try
        {
            await using var pipe = await AgentLocalControlPipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
            AgentLocalControlPipe.RequireSystemServer(pipe);
            await AgentLocalControlProtocol.WriteAsync(pipe, request, timeout.Token).ConfigureAwait(false);
            return await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(pipe, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new(false, "service_timeout");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or System.Text.Json.JsonException)
        {
            return new(false, "service_unavailable");
        }
    }
}

internal sealed class AgentLocalControlServer
{
    private readonly Func<AgentLocalControlRequest, CancellationToken, Task<AgentLocalControlResponse>> _handle;

    public AgentLocalControlServer(Func<AgentLocalControlRequest, CancellationToken, Task<AgentLocalControlResponse>> handle)
        => _handle = handle;

    public async Task RunAsync(CancellationToken ct)
    {
        if (!WindowsIdentity.GetCurrent().IsSystem)
            throw new UnauthorizedAccessException("Local control server requires SYSTEM.");
        var active = new List<Task>();
        NamedPipeServerStream? listener = AgentLocalControlPipe.CreateServer(first: true);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                active.RemoveAll(task => task.IsCompletedSuccessfully);
                if (active.Count >= 4)
                    await await Task.WhenAny(active).ConfigureAwait(false);
                active.RemoveAll(task => task.IsCompletedSuccessfully);
                await listener.WaitForConnectionAsync(ct).ConfigureAwait(false);
                var connected = listener;
                // Keep the pipe name owned across accept/close; clients cannot
                // replace it between requests with a lookalike endpoint.
                listener = AgentLocalControlPipe.CreateServer(first: false);
                active.Add(HandleConnectionAsync(connected, ct));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        finally
        {
            if (listener is not null)
                await listener.DisposeAsync().ConfigureAwait(false);
            await Task.WhenAll(active).ConfigureAwait(false);
        }
    }

    internal async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken serviceCt)
    {
        await using (pipe)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(serviceCt))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(40));
            try
            {
                // Windows impersonates the context of the last message read. Read only the bounded frame
                // before verifying identity; no request is authorized or dispatched until that succeeds.
                var request = await AgentLocalControlProtocol.ReadAsync<AgentLocalControlRequest>(pipe, timeout.Token).ConfigureAwait(false);
                var (allowed, privileged) = AgentLocalControlPipe.ClientAuthority(pipe);
                if (!allowed)
                    return;
                var response = AgentLocalControlProtocol.IsAllowed(request, privileged)
                    ? await _handle(request, timeout.Token).ConfigureAwait(false)
                    : new AgentLocalControlResponse(false, "invalid_request");
                await AgentLocalControlProtocol.WriteAsync(pipe, response, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or UnauthorizedAccessException or
                System.Security.SecurityException or System.Text.Json.JsonException or Win32Exception)
            {
                // Untrusted clients get bounded failure with no identity, raw
                // request, exception details or secrets written to logs.
            }
        }
    }
}

internal static class AgentLocalControlPipe
{
    internal const PipeAccessRights ClientRights = PipeAccessRights.ReadData | PipeAccessRights.WriteData |
        PipeAccessRights.ReadAttributes | PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize;

    internal static PipeSecurity BuildSecurity()
    {
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        security.SetOwner(system);
        foreach (var denied in new[] { WellKnownSidType.AnonymousSid, WellKnownSidType.NetworkSid })
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(denied, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        foreach (var allowed in new[] { WellKnownSidType.InteractiveSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(allowed, null), ClientRights, AccessControlType.Allow));
        return security;
    }

    internal static NamedPipeServerStream CreateServer(bool first)
        => NamedPipeServerStreamAcl.Create(AgentLocalControlProtocol.PipeName, PipeDirection.InOut, 5,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None),
            AgentLocalControlProtocol.MaxFrameBytes, AgentLocalControlProtocol.MaxFrameBytes,
            BuildSecurity(), HandleInheritability.None, (PipeAccessRights)0);

    internal static (bool Allowed, bool Privileged) ClientAuthority(NamedPipeServerStream pipe)
    {
        var allowed = false;
        var privileged = false;
        pipe.RunAsClient(() =>
        {
            using var identity = WindowsIdentity.GetCurrent(ifImpersonating: true);
            if (identity is null || !identity.IsAuthenticated || identity.IsAnonymous)
                return;
            var principal = new WindowsPrincipal(identity);
            if (principal.IsInRole(new SecurityIdentifier(WellKnownSidType.NetworkSid, null)))
                return;
            privileged = identity.IsSystem || principal.IsInRole(WindowsBuiltInRole.Administrator);
            allowed = privileged || principal.IsInRole(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null));
        });
        return (allowed, privileged);
    }

    internal static async Task<NamedPipeClientStream> ConnectAsync(CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            // GENERIC_WRITE includes FILE_CREATE_PIPE_INSTANCE on Windows.
            // Request only the specific data rights granted in the DACL.
            var handle = CreateFileW(@"\\.\pipe\" + AgentLocalControlProtocol.PipeName,
                (uint)ClientRights, 0, IntPtr.Zero, 3, 0x40000000 | 0x00100000 | 0x00020000, IntPtr.Zero);
            if (!handle.IsInvalid)
                return new NamedPipeClientStream(PipeDirection.InOut, true, true, handle);
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            if (error is not (2 or 231) || DateTimeOffset.UtcNow >= deadline)
                throw new Win32Exception(error);
            await Task.Delay(50, ct).ConfigureAwait(false);
        }
    }

    internal static void RequireSystemServer(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var processId))
            throw new UnauthorizedAccessException("Unverified control server.");
        using var manager = OpenSCManagerW(null, null, 1);
        using var service = OpenServiceW(manager, ServiceInstaller.ServiceName, 0x0001 | 0x0004);
        if (manager.IsInvalid || service.IsInvalid ||
            !QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatusProcess>(), out _) ||
            status.CurrentState != 4 || status.ProcessId == 0 || status.ProcessId != processId)
            throw new UnauthorizedAccessException("Unverified control server.");
        // SCM query rights are available to a normal interactive user; querying
        // another process's SYSTEM token would unnecessarily require elevation.
        QueryServiceConfigW(service, IntPtr.Zero, 0, out var required);
        if (required is <= 0 or > 32768)
            throw new UnauthorizedAccessException("Unverified control server.");
        var buffer = Marshal.AllocHGlobal(required);
        try
        {
            if (!QueryServiceConfigW(service, buffer, required, out _))
                throw new UnauthorizedAccessException("Unverified control server.");
            var config = Marshal.PtrToStructure<ServiceConfig>(buffer);
            if (!string.Equals(Marshal.PtrToStringUni(config.ServiceStartName), "LocalSystem", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Unverified control server.");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenSCManagerW(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ServiceHandle OpenServiceW(ServiceHandle manager, string service, uint access);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(ServiceHandle service, int level, out ServiceStatusProcess status, int size, out int required);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigW(ServiceHandle service, IntPtr config, int size, out int required);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    private sealed class ServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public ServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode,
            CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceConfig
    {
        public uint ServiceType, StartType, ErrorControl;
        public IntPtr BinaryPathName, LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies, ServiceStartName, DisplayName;
    }
}
