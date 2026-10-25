using System.IO.Pipes;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Unit-tier support evidence: the accept loop itself needs SYSTEM, so these cover the pieces it relies on
/// (per-connection timeout answer and reaping of finished handlers) over an in-process pipe with a private name.
/// </summary>
public sealed class AgentLocalControlPipeTimeoutTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private static async Task<AgentLocalControlResponse?> RoundTripAsync(
        AgentLocalControlServer server, CancellationToken serviceCt)
    {
        var name = "cerberus-test-" + Guid.NewGuid().ToString("N");
        var serverPipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(Wait);
        var accept = serverPipe.WaitForConnectionAsync(timeout.Token);
        await client.ConnectAsync(timeout.Token);
        await accept;
        var run = server.HandleConnectionAsync(serverPipe, serviceCt);
        await AgentLocalControlProtocol.WriteAsync(client, new AgentLocalControlRequest("status"), timeout.Token);
        AgentLocalControlResponse? response;
        try { response = await AgentLocalControlProtocol.ReadAsync<AgentLocalControlResponse>(client, timeout.Token); }
        catch (EndOfStreamException) { response = null; }
        catch (IOException) { response = null; }
        await run.WaitAsync(Wait);
        return response;
    }

    [Fact]
    public async Task HandlerTimeout_AnswersServiceTimeout_RepeatedTimeoutsKeepHandlerHealthy()
    {
        var calls = 0;
        var server = new AgentLocalControlServer((_, _) =>
            Interlocked.Increment(ref calls) <= 6
                ? throw new TaskCanceledException("backend timeout")
                : Task.FromResult(new AgentLocalControlResponse(true, "ok")));

        for (var i = 0; i < 6; i++)
        {
            var response = await RoundTripAsync(server, CancellationToken.None);
            Assert.NotNull(response);
            Assert.False(response!.Success);
            Assert.Equal("service_timeout", response.Code);
        }

        var next = await RoundTripAsync(server, CancellationToken.None);
        Assert.True(next!.Success);
        Assert.Equal("ok", next.Code);
    }

    [Fact]
    public async Task ConnectionDeadline_CancelsHandler_StillDeliversServiceTimeout()
    {
        var server = new AgentLocalControlServer(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new AgentLocalControlResponse(true, "ok");
        })
        { RequestDeadline = TimeSpan.FromMilliseconds(200) };

        var response = await RoundTripAsync(server, CancellationToken.None);

        Assert.NotNull(response);
        Assert.False(response!.Success);
        Assert.Equal("service_timeout", response.Code);
    }

    [Fact]
    public async Task ReapCompleted_RemovesFaultedAndCanceledTasks_AndKeepsRunningOnes()
    {
        var running = new TaskCompletionSource();
        var cancelled = new TaskCompletionSource();
        cancelled.SetCanceled();
        var faulted = new TaskCompletionSource();
        faulted.SetException(new TaskCanceledException("backend timeout"));
        var active = new List<Task> { faulted.Task, Task.CompletedTask, cancelled.Task, running.Task };

        AgentLocalControlServer.ReapCompleted(active);

        Assert.Equal(new[] { running.Task }, active);
        running.SetResult();
        await running.Task;
    }

    [Fact]
    public async Task ReapCompleted_RethrowsGenuineHandlerFault_AfterRemovingFinishedTasks()
    {
        var running = new TaskCompletionSource();
        var cancelled = new TaskCompletionSource();
        cancelled.SetCanceled();
        var faulted = new TaskCompletionSource();
        faulted.SetException(new InvalidOperationException("handler defect"));
        var active = new List<Task> { faulted.Task, cancelled.Task, running.Task };

        Assert.Throws<InvalidOperationException>(() => AgentLocalControlServer.ReapCompleted(active));

        Assert.Equal(new[] { running.Task }, active);
        running.SetResult();
        await running.Task;
    }

    [Fact]
    public async Task ServiceShutdown_DuringHandler_EndsConnectionWithoutResponseOrFault()
    {
        using var shutdown = new CancellationTokenSource();
        var started = new TaskCompletionSource();
        var server = new AgentLocalControlServer(async (_, ct) =>
        {
            started.SetResult();
            await Task.Delay(Timeout.Infinite, ct);
            return new AgentLocalControlResponse(true, "ok");
        });

        var round = RoundTripAsync(server, shutdown.Token);
        await started.Task.WaitAsync(Wait);
        shutdown.Cancel();

        Assert.Null(await round);
    }
}
