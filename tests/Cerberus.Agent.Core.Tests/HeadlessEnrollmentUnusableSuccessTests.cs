using System.Net;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>A 2xx the agent cannot use has already spent the one-time proof: exit 4, one request, nothing saved.</summary>
public sealed class HeadlessEnrollmentUnusableSuccessTests
{
    [Fact]
    public async Task Oversized_success_body_exits_four_and_stores_nothing()
    {
        // No Content-Length: the size limit has to be enforced while reading the stream.
        // A valid success body plus trailing whitespace: without the limit it would parse and enroll (exit 0).
        var (result, handler, store, log) = await Run(() => new StreamContent(new OversizedStream(ValidBody, 64 * 1024 + 1)));

        AssertSpentProof(result, handler, store, log);
    }

    [Fact]
    public async Task Escaped_lone_surrogate_in_success_body_exits_four_and_stores_nothing()
    {
        var body = "{\"agent_id\":\"agent-0001\",\"tenant_id\":\"t\",\"agent_refresh_token\":\"\\ud800\"}";
        var (result, handler, store, log) = await Run(() => new StringContent(body, Encoding.UTF8, "application/json"));

        AssertSpentProof(result, handler, store, log);
    }

    [Fact]
    public async Task Invalid_utf8_byte_in_success_body_exits_four_and_stores_nothing()
    {
        byte[] head = Encoding.UTF8.GetBytes("{\"agent_id\":\"agent-0001\",\"tenant_id\":\"t");
        byte[] tail = Encoding.UTF8.GetBytes("\",\"agent_refresh_token\":\"rt-secret\"}");
        var bytes = head.Append((byte)0xFF).Concat(tail).ToArray();
        var (result, handler, store, log) = await Run(() => new ByteArrayContent(bytes));

        AssertSpentProof(result, handler, store, log);
    }

    private const string ValidBody = "{\"agent_id\":\"agent-0001\",\"tenant_id\":\"tenant-1\",\"agent_refresh_token\":\"rt-secret\"}";

    [Fact]
    public async Task Success_body_that_throws_IOException_mid_read_exits_four_without_retry()
    {
        var (result, handler, store, log) = await Run(() => new StreamContent(new FailingStream()));

        AssertSpentProof(result, handler, store, log);
    }

    private static void AssertSpentProof(HeadlessEnrollmentResult result, CountingHandler handler, HeadlessEnrollmentTests.MemoryStore store, HeadlessEnrollmentTests.CaptureLog log)
    {
        Assert.Equal(HeadlessEnrollmentExit.NewProofRequired, result.ExitCode);
        Assert.Equal("response_invalid", result.Code);
        Assert.Equal(1, handler.Count);
        Assert.Null(store.Saved);
        Assert.Equal(0, store.SaveCount);
        Assert.DoesNotContain(HeadlessEnrollmentTests.Proof(), log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("rt-secret", log.Text, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", log.Text, StringComparison.Ordinal);
    }

    private static async Task<(HeadlessEnrollmentResult, CountingHandler, HeadlessEnrollmentTests.MemoryStore, HeadlessEnrollmentTests.CaptureLog)> Run(Func<HttpContent> content)
    {
        var handler = new CountingHandler(content);
        var store = new HeadlessEnrollmentTests.MemoryStore();
        var log = new HeadlessEnrollmentTests.CaptureLog();
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.example") };
        var result = await new HeadlessEnrollment(http, log: log, time: new HeadlessEnrollmentTests.ImmediateTimeProvider())
            .RunAsync(HeadlessEnrollmentTests.Proof(), HeadlessEnrollmentTests.Options(), new AgentLifecycleSnapshot(), false, store, CancellationToken.None);
        return (result, handler, store, log);
    }

    private sealed class CountingHandler(Func<HttpContent> content) : HttpMessageHandler
    {
        public int Count { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Count++;
            if (Count > 1)
                throw new InvalidOperationException("Unexpected extra request.");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content() });
        }
    }

    private abstract class ReadOnlyStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class OversizedStream(string prefix, int total) : ReadOnlyStream
    {
        private readonly byte[] _prefix = Encoding.UTF8.GetBytes(prefix);
        private int _sent;

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var n = Math.Min(Math.Min(buffer.Length, 4096), total - _sent);
            for (var i = 0; i < n; i++)
                buffer.Span[i] = _sent + i < _prefix.Length ? _prefix[_sent + i] : (byte)' ';
            _sent += n;
            return ValueTask.FromResult(n);
        }
    }

    private sealed class FailingStream : ReadOnlyStream
    {
        private bool _first = true;

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_first)
                throw new IOException("connection reset");
            _first = false;
            var first = Encoding.UTF8.GetBytes("{\"agent_refresh_token\":\"rt-secret");
            first.CopyTo(buffer.Span);
            return ValueTask.FromResult(first.Length);
        }
    }
}
