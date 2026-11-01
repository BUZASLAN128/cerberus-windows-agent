using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentWakeupHandshakeTests
{
    [Fact]
    public async Task ShortPlannedRotationKeepsBackoffWithoutAuthMutation()
    {
        using var http = new HttpClient { BaseAddress = new Uri("https://collector.example") };
        var secrets = new FakeSecrets();
        var tokens = new FakeToken();
        var api = new AgentApiClient(http, secrets, tokens, new CaptureSigner())
        {
            WakeupInvokerFactory = () => new HttpMessageInvoker(new BlockingUpgradeHandler()),
            WakeupConnectionLifetime = TimeSpan.FromMilliseconds(50),
        };
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var log = new RecordingLogger();
        async Task Listen(JsonElement discovery, AgentWakeupSignal signal, CancellationToken ct)
        {
            await api.ListenForWakeupsOnceAsync(discovery, signal, ct);
            completed.TrySetResult();
        }
        await using var client = new AgentWakeupClient(api, new AgentWakeupSignal(), Listen, log);
        using var json = JsonDocument.Parse($"{{\"version\":1,\"path\":\"/api/v1/agents/{AgentId}/wakeup\"}}");
        await client.ConfigureAsync(json.RootElement, default);
        await completed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Wait.UntilAsync(() => client.ConsecutiveFailures == 1, "short-connection backoff");
        Assert.Equal(1, client.ConsecutiveFailures); // A sub-minute connection is not a stable-open proof.
        Assert.DoesNotContain(log.Lines, line => line.Contains("connection unavailable"));
        Assert.Equal(0, secrets.Clears);
        Assert.Equal(0, tokens.Refreshes);
    }

    private sealed class BlockingUpgradeHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var key = request.Headers.GetValues("Sec-WebSocket-Key").Single();
            var accept = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            var response = new HttpResponseMessage(HttpStatusCode.SwitchingProtocols)
            {
                Version = HttpVersion.Version11,
                Content = new UpgradeContent(new BlockingStream()),
            };
            response.Headers.TryAddWithoutValidation("Connection", "Upgrade");
            response.Headers.TryAddWithoutValidation("Upgrade", "websocket");
            response.Headers.TryAddWithoutValidation("Sec-WebSocket-Accept", accept);
            return Task.FromResult(response);
        }
    }

    private sealed class BlockingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return 0;
        }
        public override void Write(byte[] buffer, int offset, int count) { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
