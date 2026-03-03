using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;

namespace Cerberus.Agent.App;

internal static class SingleInstanceGuard
{
    // Tray-only: keep this stable so all versions compete on the same single-instance lock.
    private const string MutexName = "Global\\CerberusAgent.Tray.SingleInstance";
    private const string PipeName = "CerberusAgent.Tray.SingleInstancePipe";

    private static Mutex? _mutex;
    private static CancellationTokenSource? _serverCts;

    public static bool EnsureOrExit()
    {
        // Only enforce for interactive tray/UI. Service/register/export modes bypass this.
        // This method is called only from the tray startup path in Program.cs.
        if (TryAcquireMutex())
            return true;

        var choice = System.Windows.MessageBox.Show(
            "Eski bir CERBERUS Agent oturumu zaten calisiyor.\n\nKapatmak ister misiniz?",
            "CERBERUS Agent",
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Question,
            System.Windows.MessageBoxResult.No);

        if (choice != System.Windows.MessageBoxResult.Yes)
            return false;

        // Best-effort: ask the other instance to exit gracefully.
        TryRequestExitViaPipe();

        // Wait a bit for the mutex to be released.
        var deadline = DateTimeOffset.UtcNow.AddSeconds(4);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (TryAcquireMutex())
                return true;
            Thread.Sleep(250);
        }

        // Fall back to force-kill same-user instances we can access.
        TryForceKillOtherTrayInstances();

        deadline = DateTimeOffset.UtcNow.AddSeconds(3);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (TryAcquireMutex())
                return true;
            Thread.Sleep(250);
        }

        System.Windows.MessageBox.Show(
            "Eski oturum kapatilamadi. Lutfen Task Manager'dan 'Cerberus.Agent.App' surecini kapatip tekrar deneyin.",
            "CERBERUS Agent",
            System.Windows.MessageBoxButton.OK,
            System.Windows.MessageBoxImage.Warning);
        return false;
    }

    public static void StartExitListener(Action onExitRequested)
    {
        _serverCts ??= new CancellationTokenSource();
        var ct = _serverCts.Token;

        _ = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await using var server = new NamedPipeServerStream(
                        PipeName,
                        PipeDirection.InOut,
                        maxNumberOfServerInstances: 1,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);

                    await server.WaitForConnectionAsync(ct);

                    using var ms = new MemoryStream();
                    var buf = new byte[4096];
                    int n;
                    while ((n = await server.ReadAsync(buf, ct)) > 0)
                    {
                        ms.Write(buf, 0, n);
                        if (!server.IsConnected)
                            break;
                        // Short messages expected.
                        if (ms.Length > 64 * 1024)
                            break;
                    }

                    var msg = Encoding.UTF8.GetString(ms.ToArray()).Trim();
                    if (string.Equals(msg, "exit", StringComparison.OrdinalIgnoreCase))
                    {
                        System.Windows.Application.Current.Dispatcher.Invoke(() =>
                        {
                            try { onExitRequested(); } catch { }
                        });
                    }
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch
                {
                    // Keep server alive; transient pipe errors are fine.
                    await Task.Delay(250, ct);
                }
            }
        }, ct);
    }

    public static void StopExitListener()
    {
        try { _serverCts?.Cancel(); } catch { }
    }

    private static bool TryAcquireMutex()
    {
        try
        {
            var createdNew = false;
            if (_mutex is null)
                _mutex = new Mutex(initiallyOwned: true, name: MutexName, createdNew: out createdNew);

            if (createdNew)
                return true;

            // If not created new, we didn't get initial ownership. Try to acquire quickly.
            return _mutex is not null && _mutex.WaitOne(0);
        }
        catch
        {
            return false;
        }
    }

    private static void TryRequestExitViaPipe()
    {
        try
        {
            using var client = new NamedPipeClientStream(
                ".",
                PipeName,
                PipeDirection.Out,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Identification);

            client.Connect(timeout: 700);
            var bytes = Encoding.UTF8.GetBytes("exit");
            client.Write(bytes, 0, bytes.Length);
            client.Flush();
        }
        catch
        {
            // Old versions may not host the pipe; ignore.
        }
    }

    private static void TryForceKillOtherTrayInstances()
    {
        try
        {
            var me = Environment.ProcessId;
            var myUser = WindowsIdentity.GetCurrent().User?.Value;

            foreach (var p in System.Diagnostics.Process.GetProcessesByName("Cerberus.Agent.App"))
            {
                if (p.Id == me)
                    continue;

                // Best-effort: only kill processes we can inspect (same-user, non-elevated).
                // AccessDenied here usually means it's a service/elevated instance; skip those.
                try
                {
                    var otherUser = GetProcessUserSid(p);
                    if (myUser is not null && otherUser is not null && !string.Equals(myUser, otherUser, StringComparison.Ordinal))
                        continue;

                    p.Kill(entireProcessTree: false);
                }
                catch
                {
                    // ignore
                }
            }
        }
        catch
        {
            // ignore
        }
    }

    private static string? GetProcessUserSid(System.Diagnostics.Process p)
    {
        try
        {
            // Requires QueryLimitedInformation rights; may throw for protected/elevated processes.
            using var identity = new WindowsIdentity(p.Handle);
            return identity.User?.Value;
        }
        catch
        {
            return null;
        }
    }
}
