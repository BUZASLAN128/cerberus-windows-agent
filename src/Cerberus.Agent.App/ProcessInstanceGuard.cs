using System.IO.Pipes;
using System.Text;

namespace Cerberus.Agent.App;

public sealed class ProcessInstanceGuard : IDisposable
{
    private readonly Mutex _mutex;
    private readonly string _pipeName;
    private readonly CancellationTokenSource _serverCts = new();
    private bool _disposed;

    private ProcessInstanceGuard(Mutex mutex, string pipeName)
    {
        _mutex = mutex;
        _pipeName = pipeName;
    }

    public static bool TryAcquire(
        string mutexName,
        string pipeName,
        string? signalExisting,
        out ProcessInstanceGuard? guard)
    {
        guard = null;
        Mutex? mutex = null;

        try
        {
            mutex = new Mutex(initiallyOwned: false, name: mutexName);
            try
            {
                if (mutex.WaitOne(0))
                {
                    guard = new ProcessInstanceGuard(mutex, pipeName);
                    return true;
                }
            }
            catch (AbandonedMutexException)
            {
                guard = new ProcessInstanceGuard(mutex, pipeName);
                return true;
            }

            if (!string.IsNullOrWhiteSpace(signalExisting))
                TrySignalExisting(pipeName, signalExisting);

            mutex.Dispose();
            return false;
        }
        catch
        {
            mutex?.Dispose();
            return false;
        }
    }

    public void StartSignalListener(Action<string> onSignal)
    {
        var ct = _serverCts.Token;

        _ = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await using var server = new NamedPipeServerStream(
                        _pipeName,
                        PipeDirection.In,
                        maxNumberOfServerInstances: 1,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);

                    await server.WaitForConnectionAsync(ct);

                    var buffer = new byte[128];
                    var read = await server.ReadAsync(buffer, ct);
                    if (read <= 0)
                        continue;

                    var message = Encoding.UTF8.GetString(buffer, 0, read).Trim();
                    if (message.Length > 0)
                        onSignal(message);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch
                {
                    try { await Task.Delay(250, ct); } catch { return; }
                }
            }
        }, ct);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        try { _serverCts.Cancel(); } catch { }
        _serverCts.Dispose();
        try { _mutex.ReleaseMutex(); } catch { }
        _mutex.Dispose();
    }

    private static void TrySignalExisting(string pipeName, string message)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.Out, PipeOptions.Asynchronous);
            client.Connect(timeout: 300);
            var bytes = Encoding.UTF8.GetBytes(message);
            client.Write(bytes, 0, bytes.Length);
            client.Flush();
        }
        catch
        {
            // Existing versions may not expose a pipe; duplicate process should still exit.
        }
    }
}
