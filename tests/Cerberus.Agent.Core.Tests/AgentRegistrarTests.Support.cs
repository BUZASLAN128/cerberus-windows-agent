using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentRegistrarTests
{
    private static AgentRegistrar NewRegistrar(HttpClient http) => new(
        http,
        new CaptureSecretStore(),
        new StubKeyPairs("priv-pem", "pub-pem"),
        log: NullAgentLogger.Instance);

    private static Task<AgentIdentity> Register(AgentRegistrar registrar) => registrar.RegisterAsync(
        oauthToken: "Bearer tok",
        backendUrlForStorage: "http://backend",
        deviceFingerprint: "fp",
        agentVersion: "1.2.3",
        buildId: "build-abc",
        buildChannel: "dev",
        ct: CancellationToken.None);

    private static Task<AgentIdentity> Register(AgentRegistrar registrar, CancellationToken ct) => registrar.RegisterAsync(
        oauthToken: "Bearer tok",
        backendUrlForStorage: "http://backend",
        deviceFingerprint: "fp",
        agentVersion: "1.2.3",
        buildId: "build-abc",
        buildChannel: "dev",
        ct: ct);

    private static string RegisterResponseJson() =>
        "{\"agent_id\":\"a1\",\"tenant_id\":\"t1\",\"agent_refresh_token\":\"rt1\",\"jwt_public_key_pem\":null,\"telemetry_base_url\":\"http://telemetry.test\"}";

    private static string PadToLength(string value, int length)
    {
        var current = Encoding.UTF8.GetByteCount(value);
        Assert.True(current <= length);
        return value + new string(' ', length - current);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public HttpRequestMessage? CapturedRequest { get; private set; }
        public string? CapturedBody { get; private set; }
        public HttpResponseMessage Response => _response;

        public CaptureHandler(HttpResponseMessage response, bool headersArriveAfterDeadline = false)
        {
            _response = response;
            _headersArriveAfterDeadline = headersArriveAfterDeadline;
        }

        private readonly bool _headersArriveAfterDeadline;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedRequest = request;
            if (request.Content is not null)
                CapturedBody = await request.Content.ReadAsStringAsync(cancellationToken);
            if (_headersArriveAfterDeadline)
            {
                // A transport that ignores cancellation: the headers come back only once the deadline has fired.
                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                }

                // HttpClient's timeout and the caller's deadline are separate timers with no guaranteed order;
                // wait out any skew so the deadline has fired before the headers are returned.
                await Task.Delay(TimeSpan.FromMilliseconds(500), CancellationToken.None);
            }

            return _response;
        }
    }

    private sealed class CountingContent : HttpContent
    {
        private readonly byte[] _bytes;

        public CountingContent(byte[] bytes) => _bytes = bytes;
        public int BytesRead { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new NotSupportedException();

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromResult<Stream>(new CountingStream(_bytes, this));

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        private sealed class CountingStream : MemoryStream
        {
            private readonly byte[] _bytes;
            private readonly CountingContent _owner;
            public CountingStream(byte[] bytes, CountingContent owner) : base(bytes, writable: false)
            {
                _bytes = bytes;
                _owner = owner;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                var read = base.Read(buffer, offset, count);
                _owner.BytesRead += read;
                return read;
            }

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                var remaining = _bytes.Length - (int)Position;
                var read = Math.Min(buffer.Length, Math.Max(remaining, 0));
                if (read > 0)
                {
                    _bytes.AsMemory((int)Position, read).CopyTo(buffer);
                    Position += read;
                }
                _owner.BytesRead += read;
                return ValueTask.FromResult(read);
            }
        }
    }

    private sealed class ThrowingContent : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new IOException("body unavailable");
        protected override Task<Stream> CreateContentReadStreamAsync() => throw new IOException("body unavailable");
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }

    // Far above any scheduling delay; only reached if the client stops honoring its deadline.
    private static readonly TimeSpan HangGuard = TimeSpan.FromSeconds(30);

    private sealed class StallingContent : HttpContent
    {
        private readonly byte[] _prefix;

        public StallingContent(string? prefix = null) => _prefix = Encoding.UTF8.GetBytes(prefix ?? string.Empty);

        /// <summary>A body read began with a token that was not yet cancelled.</summary>
        public bool ReadStartedWithLiveToken { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new NotSupportedException();
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new StallingStream(_prefix, token => ReadStartedWithLiveToken |= !token.IsCancellationRequested));
        protected override bool TryComputeLength(out long length) { length = 0; return false; }

        private sealed class StallingStream : Stream
        {
            private readonly byte[] _prefix;
            private int _offset;

            private readonly Action<CancellationToken> _onRead;

            public StallingStream(byte[] prefix, Action<CancellationToken> onRead) => (_prefix, _onRead) = (prefix, onRead);

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => 0;
            public override long Position { get => 0; set => throw new NotSupportedException(); }
            public override void Flush() => throw new NotSupportedException();
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                _onRead(cancellationToken);
                if (_offset < _prefix.Length)
                {
                    var count = Math.Min(buffer.Length, _prefix.Length - _offset);
                    _prefix.AsSpan(_offset, count).CopyTo(buffer.Span);
                    _offset += count;
                    return count;
                }

                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return 0;
            }
        }
    }

    private sealed class CaptureSecretStore : ISecretStore
    {
        public CancellationTokenSource? CancelAfterSave { get; init; }
        public (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)? Existing { get; init; }
        public (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)? LastSaved { get; private set; }

        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct)
        {
            LastSaved = (identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey);
            CancelAfterSave?.Cancel();
            return Task.CompletedTask;
        }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            return Existing is { } existing
                ? Task.FromResult(existing)
                : throw new FileNotFoundException("No stored test registration.");
        }

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StubKeyPairs : IKeyPairGenerator
    {
        private readonly string _priv;
        private readonly string _pub;

        public int GenerateCount { get; private set; }

        public StubKeyPairs(string priv, string pub)
        {
            _priv = priv;
            _pub = pub;
        }

        public (string PrivateKeyPem, string PublicKeyPem) GenerateKeyPair(int keySize)
        {
            GenerateCount++;
            return (_priv, _pub);
        }
    }
}
